const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
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

const client = redis.createClient({
  url: "redis://default:redis@localhost:6379/2"
});
const app = express();
const PORT = 8000;
const DEFAULT_KEY_TTL_SECONDS = 10;
const JWT_SECRET_KEY = "my_secret_key";
const users = [
  {
    id: 1,
    username: "admin"
  },
  {
    id: 2,
    username: "ertan.sinik"
  }
];

/// Redis client başlatma
(async () => {
  client.on("connect", () => {
    console.log("Redis sunucusuna bağlanıldı.");
  });
  client.on("error", (err) => {
    console.error("Redis hatası:", err);
  });

  await client.connect();
})();

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

/// JWT Oluşturma
function signJwt(payload) {
  return jwt.sign(payload, JWT_SECRET_KEY, {
    expiresIn: (DEFAULT_KEY_TTL_SECONDS || 2) * 60 /// varsayılan 2 dakika
  });
}

/// JWT Doğrulama
function verifyJwt(token) {
  try {
    return jwt.verify(token, JWT_SECRET_KEY);
  } catch (err) {
    console.error("Jwt doğrulama hatası:", err.message);
    return null;
  }
}

async function clearRSACacheForUser(username) {
  await client.del(`${username}:pair:client_public_key`);
  await client.del(`${username}:pair:server_private_key`);
  await client.del(`${username}:pair:server_public_key`);
}

/**
 * İstemciden gelen RSA public key'i pem formatında önbelleğe alır.
 */
async function cacheClientRSAPublicKey(username, publicKey) {
  const redisPublicKey = await client.get(`${username}:pair:client_public_key`);

  if (!redisPublicKey) {
    if (!publicKey) return null;

    await client.set(`${username}:pair:client_public_key`, publicKey, {
      EX: (DEFAULT_KEY_TTL_SECONDS || 2) * 60
    });

    return publicKey;
  } else return redisPublicKey;
}

/**
 * Kullanıcı adına ait provider RSA anahtar eşini önbelleğe alır.
 */
async function cacheServerRSAPair(username, privateKey, publicKey) {
  const redisPrivateKey = await client.get(
    `${username}:pair:server_private_key`
  );
  const redisPublicKey = await client.get(`${username}:pair:server_public_key`);

  if (!redisPrivateKey || !redisPublicKey) {
    if (!privateKey || !publicKey) return { privateKey: null, publicKey: null };
    else if (privateKey && publicKey) {
      await client.set(`${username}:pair:server_private_key`, privateKey, {
        EX: (DEFAULT_KEY_TTL_SECONDS || 2) * 60
      });
      await client.set(`${username}:pair:server_public_key`, publicKey, {
        EX: (DEFAULT_KEY_TTL_SECONDS || 2) * 60
      });

      return { privateKey, publicKey };
    } else return { privateKey: null, publicKey: null };
  } else return { privateKey: redisPrivateKey, publicKey: redisPublicKey };
}

app.get("/__health", (_, res) => {
  res.status(200).send("I'm alive!");
});

/**
 * 1. Adım: İstemci tarafı, şifrelenmemiş halde public key'i sunucuya gönderir.
 * 2. Adım: Sunucu, public key'i önbelleğe alır.
 * 3. Adım: Sunucu, istemcinin public key'i ile response'u şifreler ve sonra onu döner.
 */
app.post("/login", async (req, res) => {
  console.info("/login route çalıştı");

  try {
    /// İstemci tarafından gelen şifresiz veriyi al
    const { public_key: client_public_key, username } = req.body;
    const dbUser = users.find((user) => user.username === username);

    /// Kullanıcı adıyla eşleşen kullanıcı yoksa, hata döndür
    if (dbUser) {
      await clearRSACacheForUser(username);

      /// Her login isteği için gelen kullanıcıya bir RSA key pair oluşturulur. Bunun sebebi kullanıcıların oturumlarının güvenliğini sağlamaktır. RSA key pair aslında bir oturum anahtarı gibi düşünülebilir.
      const {
        privateKey: userServerPrivateKey,
        publicKey: userServerPublicKey
      } = generateKeyPairSync("rsa", {
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

      /// İstemci tarafından gönderilen public key'i önbelleğe al
      const cachedClientPublicKeyPem = await cacheClientRSAPublicKey(
        username,
        client_public_key
      );

      /// Kullanıcı adına ait sunucunun RSA key pair'ini önbelleğe al
      const { publicKey } = await cacheServerRSAPair(
        username,
        userServerPrivateKey,
        userServerPublicKey
      );

      res.status(200).send(
        /// İstemcinin RSA public key'i ile şifrelenmiş response'u döndür
        encryptResponse(cachedClientPublicKeyPem, {
          message: "Hoş geldiniz!",
          data: {
            public_key: publicKey,
            token: signJwt({ username, id: dbUser.id })
          }
        })
      );
    } /// Kullanıcı adıyla eşleşmesi beklenen RSA public key gelen istekte yoksa, hata döndür
    else if (!client_public_key)
      res.status(424).send({
        message: "Giriş isteğinize dair bilgiler eksik.",
        error: "424 Failed Dependency"
      });
    /// Kullanıcı bulunamadı
    else
      res.status(404).send({
        message: "Bilgileniriz eksik ya da hatalı.",
        error: "404 Not Found"
      });
  } catch (error) {
    console.info("/login route hatası");
    console.error(error);

    res.status(500).send({
      message:
        "Giriş yaparken bir hata oluştu, lütfen sistem destek ekibinize danışın.",
      error: "500 Internal Server Error"
    });
  }
});

app.post("/profile", async (req, res) => {
  console.info("/profile route çalıştı");

  try {
    /// İstemci tarafından gelen şifreli verileri al
    const { data, key, iv } = req.body;

    /// Header'dan JWT token'ı al
    const [, jwtToken] = req.headers.authorization.split(" ");

    /// JWT token'ı doğrula
    const sessionObject = verifyJwt(jwtToken);

    /// JWT token'ı doğrulanamazsa, hata döndür
    if (!sessionObject)
      res.status(401).send({
        message: "Oturumunuz geçersiz, lütfen tekrar giriş yapın.",
        error: "401 Unauthorized"
      });
    else {
      const { privateKey } = await cacheServerRSAPair(sessionObject.username);

      if (!privateKey)
        res.status(424).send({
          message:
            "Oturumunuza dair bilgiler eksik, lütfen tekrar giriş yapın. B",
          error: "424 Failed Dependency"
        });
      else {
        const aesKey = privateDecrypt(
          {
            key: privateKey,
            padding: constants.RSA_PKCS1_OAEP_PADDING
          },
          Buffer.from(key, "base64")
        );
        const decryptedData = JSON.parse(decryptRequest(data, aesKey, iv));

        console.log(
          "Profile Request Data: ",
          JSON.stringify(decryptedData, null, 2)
        );

        const clientRSAPublicKey = await cacheClientRSAPublicKey(
          sessionObject.username
        );

        if (!clientRSAPublicKey)
          res.status(424).send({
            message:
              "Oturumunuza dair bilgiler eksik, lütfen tekrar giriş yapın. A",
            error: "424 Failed Dependency"
          });
        else
          res.status(200).send(
            encryptResponse(clientRSAPublicKey, {
              message: "Profilin çok güzel!"
            })
          );
      }
    }
  } catch (error) {
    console.info("/profile route hatası");
    console.error(error);

    res.status(500).send({
      message: "Bir hata oluştu, lütfen sistem destek ekibinize danışın.",
      error: "500 Internal Server Error"
    });
  }
});

app.listen(PORT, () => {
  console.log(`Sunucu http://localhost:${PORT} adresinde çalışıyor`);
});
