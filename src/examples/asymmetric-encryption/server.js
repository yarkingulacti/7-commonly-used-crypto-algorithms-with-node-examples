const express = require("express");
const cors = require("cors"); // CORS modülünü ekle
const {
  generateKeyPairSync,
  privateDecrypt,
  publicEncrypt,
  randomBytes,
  createCipheriv,
  createDecipheriv,
  constants
} = require("crypto");
const redis = require("redis");

// Redis istemcisi oluştur
const client = redis.createClient({
  url: "redis://default:redis@localhost:6379/2"
});
const app = express();

// Bağlantı açıldığında
client.on("connect", () => {
  console.log("Redis sunucusuna bağlanıldı.");
});

// Hata durumunda
client.on("error", (err) => {
  console.error("Redis hatası:", err);
});

// Redis bağlantısını başlat
(async () => {
  await client.connect();
})();

const { privateKey, publicKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: {
    type: "spki",
    format: "pem"
  },
  privateKeyEncoding: {
    type: "pkcs8",
    format: "pem"
  }
});
const PORT = 8000;
const users = [];

app.use(cors());
app.use(
  express.json({
    limit: "5mb"
  })
);
app.use(express.urlencoded({ extended: true }));

/**
 * 1. Adım: AES anahtarı ve IV oluştur
 * 2. Adım: Fonksiyona gelen veriyi AES ile şifrele
 * 3. Adım: AES anahtarını RSA ile şifrele
 * 4. Adım: Şifrelenmiş veriyi, şifrelenmiş anahtar ve IV'yi döndür
 */
function encryptResponse(publicKeyPem, data) {
  // 1. AES anahtarı ve IV oluştur
  const aesKey = randomBytes(32); // 256-bit AES anahtarı
  const iv = randomBytes(16); // 128-bit IV

  // 2. Veriyi AES ile şifrele
  const cipher = createCipheriv("aes-256-cbc", aesKey, iv);
  let encryptedData = cipher.update(JSON.stringify(data), "utf8", "base64");
  encryptedData += cipher.final("base64");

  // 3. AES anahtarını RSA PKCS#1 v1.5 Padding değeri ile şifrele
  const encryptedKey = publicEncrypt(
    { key: publicKeyPem, padding: constants.RSA_PKCS1_PADDING },
    aesKey
  );

  console.log("aes key base64", aesKey.toString("base64"));
  console.log("iv", iv.toString("base64"));

  // 4. Şifrelenmiş veri, şifrelenmiş anahtar ve IV'yi döndür
  return {
    data: encryptedData,
    key: encryptedKey,
    iv: iv.toString("base64")
  };
}

function decryptRequest(data, keyBase64, ivBase64) {
  // Key ve IV'yi Base64'ten çöz
  const key = Buffer.from(keyBase64, "base64");
  const iv = Buffer.from(ivBase64, "base64");

  // Uzunlukları kontrol et
  if (key.length !== 32) {
    throw new Error("Invalid AES key length. Expected 32 bytes for AES-256.");
  }
  if (iv.length !== 16) {
    throw new Error("Invalid IV length. Expected 16 bytes.");
  }

  // Şifre çözme işlemi
  const decipher = createDecipheriv("aes-256-cbc", key, iv);
  let decrypted = decipher.update(data, "base64", "utf-8");
  decrypted += decipher.final("utf-8");

  return decrypted;
}

async function cacheOrRetreivePublicKey(username, publicKey) {
  const redisPublicKey = await client.get(`${username}:public_key`);

  if (!redisPublicKey) {
    await client.set(`${username}:public_key`, publicKey, {
      EX: 2 * 60
    });

    return publicKey;
  } else return redisPublicKey;
}

app.get("/__health", (_, res) => {
  res.status(200).send("OK");
});

/**
 * 1. Adım: İstemci tarafı, şifrelenmemiş halde public key'i sunucuya gönderir.
 * 2. Adım: Sunucu, public key'i önbelleğe alır.
 * 3. Adım: Sunucu, istemcinin public key'i ile response'u şifreler ve sonra onu döner.
 */
app.post("/login", async (req, res) => {
  console.info("/login route çalıştı");

  /// İstemci tarafından gönderilen şifresiz veriyi al
  const { public_key, username } = req.body;

  try {
    /// İstemci tarafından gönderilen public key'i önbelleğe al
    const cachedClientPublicPem = await cacheOrRetreivePublicKey(
      username,
      public_key
    );

    /// Kullanıcı adı daha önce eklenmemişse, kullanıcıyı ekle
    if (!users.find((user) => user.username === username)) {
      users.push({ username });

      res.status(200).send(
        encryptResponse(cachedClientPublicPem, {
          message: "Kaydınız başarılı. Hoş geldiniz!",
          public_key: publicKey
        })
      );
    }
    /// Kullanıcı adı daha önce eklenmişse, hata döndür
    else
      res.status(409).send(
        encryptResponse(cachedClientPublicPem, {
          message:
            "Kullanıcı zaten var. Lütfen başka bir kullanıcı adıyla deneyin.",
          public_key: publicKey
        })
      );
  } catch (error) {
    console.info("/login route hatası");
    console.error(error);

    res.status(500);
  }
});

app.post("/profile", async (req, res) => {
  console.info("/profile route çalıştı");

  /// İstemci tarafından gelen şifreli verileri al
  const { data, key, iv } = req.body;

  console.log("Gelen body: ", req.body);

  try {
    const aesKey = privateDecrypt(
      {
        key: privateKey,
        padding: constants.RSA_PKCS1_OAEP_PADDING
      },
      Buffer.from(key, "base64")
    );

    console.log("Gelen aes key (Base64): ", aesKey.toString("base64"));

    const decryptedData = JSON.parse(decryptRequest(data, aesKey, iv));
    console.log(
      "Çözülen client verisi (JSON): " + JSON.stringify(decryptedData, null, 2)
    );

    const { username } = decryptedData;
    const publicKey = await cacheOrRetreivePublicKey(username);

    if (!publicKey)
      res.status(424).send({
        message: "Oturumunuza dair bilgiler eksik, lütfen tekrar giriş yapın.",
        error: "424 Failed Dependency"
      });
    else
      res.status(200).send(
        encryptResponse(publicKey, {
          message: "Profilin çok güzel!"
        })
      );
  } catch (error) {
    console.info("/profile route hatası");
    console.error(error);

    res.status(500);
  }
});

app.listen(PORT, () => {
  console.log(`Sunucu http://localhost:${PORT} adresinde çalışıyor`);
});
