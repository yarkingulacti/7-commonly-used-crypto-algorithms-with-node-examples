# 7 Most Popular Crytography Algorithms with Examples in Node

## ![](https://flagcdn.com/16x12/gb.png) ENGLISH

### 1. Hash

You start with an input, which can be in variable length. Then you pass it out to a hashing function. This function returns fixed length of value. The catch here is same input means same output here. It's extremly difficult for a computer to reverse engineer what the original input is. These are very useful characteristics because it helps Developers to store data without have to know the original data. An example would be stroing user's password in the database.

Hash function requires an algorith and takes an input then returns 256-bits of output that is called "digest".

> MD5 algorithm is not a secure therefore it's deprecated. SHA256 would be a good option.

> Hashes aren't sufficent enough when it comes to string passwords in database!

### 2. Salt

The fact that Hash functions always return same value, it can also mean that with same input we would get same output. This can lead to a pattern when it comes to storing passwords.

A Salt is a random value that's been added to input before it's hashed, therefore making it much harder to guess. We also need to store the salt with the hash. We can simply do that by prepending the salt to hashed output.

### 3. HMAC

It's a hashing technique but also requires a password. An example would be JWT tokens; it requires a key to hash the data. Just like Hashing, same input means same output.

### 4. Symmetric Encryption

While we are encrypting a data; we take an input, create cipher text by encrypting it, then provide a key to decryption function. In symmetric encryption there is a shared key to both encryption and decryption parties.

> Both the sender and sharer needs to know the secret. That's a big downside.

### 5. Asymmetric Encryption

This encryption requires a linked pair of keys; public and private. Public key is used to encrypt data and private key is used to decrypt data. This technique is used commonly by SSL protocol.

## ![](https://flagcdn.com/16x12/tr.png) TÜRKÇE

## 1. Hash

Bir girdi ile başlarsınız, bu değişken uzunlukta olabilir. Sonra bunu bir hash fonksiyonuna verirsiniz. Bu fonksiyon sabit uzunlukta bir değer döndürür. Burada dikkat edilmesi gereken nokta var; aynı girdi aynı çıktı anlamına gelir. Bilgisayarın orijinal girdiyi tersine mühendislikle bulması son derece zordur. Hashing'in bu özellikleri Developer'ların orijinal veriyi bilmeden veri saklaması konusunda onlara yardımcı olur. Bir örnek olarak kullanıcının şifresini veritabanında saklamak verilebilir.

Hash fonksiyonu bir algoritma gerektirir ve bir girdi alır, ardından "digest" olarak adlandırılan 256-bitlik bir çıktı döndürür.

> MD5 algoritması güvenli değildir bu yüzden kullanımdan kaldırılmıştır. SHA256 iyi bir seçenek olabilir.

> Hash'ler veritabanında şifreleri saklamak için yeterli değildir!

## 2. Salt

Hash fonksiyonlarının her zaman aynı değeri döndürmesi, aynı girdi ile aynı çıktı alınacağı anlamına gelir. Bu, şifre saklama konusunda tekrar eden pattern'lar oluşturabilir.

Salt, hash'lenmeden önce girdiye eklenen rastgele bir değerdir, bu da girdinin tahmin edilmesini çok daha zor hale getirir. Ayrıca salt'ı hash ile birlikte saklamamız gerekir. Bunu basitçe salt'ı hashlenmiş çıktıya ekleyerek yapabiliriz.

## 3. HMAC

Bu bir hash tekniğidir ama aynı zamanda bir şifre gerektirir. Bir örnek JWT token'ları olabilir; Şifrelenmiş çıktıyı üretmek için bir anahtar kullanılır. Hash'leme gibi, aynı girdi aynı çıktı anlamına gelir.

## 4. Symmetric Encryption

Veriyi şifrelerken; bir girdi alırız, bunu şifreleyerek "cipher text" oluştururuz, ardından deşifreleme fonksiyonuna bir anahtar veririz. Simetrik şifrelemede hem şifreleme hem de deşifreleme tarafları için ortak bir anahtar vardır.

> Hem gönderici hem de paylaşıcı sırrı bilmek zorundadır. Bu büyük bir dezavantajdır.

## 5. Asymmetric Encryption

Bu şifreleme, birbirine bağlı iki anahtar seti gerektirir; public ve private anahtarlar. Public anahtarı verileri şifrelemek için kullanılır ve private anahtarı verileri deşifre etmek için kullanılır. Bu teknik genellikle SSL protokolü tarafından kullanılır.
