namespace RsaEncryptionService;

using System.Security.Cryptography;

/// <summary>
/// Provides RSA encryption and decryption services along with key generation capabilities.
/// </summary>
public static class EncryptionService
{
    /// <summary>
    /// Creates a new RSA key pair consisting of public and private keys.
    /// </summary>
    /// <returns>A tuple containing the public key and private key in XML format.</returns>
    public static (string PublicKey, string PrivateKey) CreateRsaKeys()
    {
        using var rsa = RSA.Create(2048);
        var publicKeyXml = rsa.ToXmlString(false);
        var privateKeyXml = rsa.ToXmlString(true);
        return (publicKeyXml, privateKeyXml);
    }

    /// <summary>
    /// Encrypts a plain text string using RSA encryption with OAEP SHA-256 padding.
    /// </summary>
    /// <param name="plainText">The text to encrypt.</param>
    /// <param name="publicKeyXml">The RSA public key in XML format.</param>
    /// <returns>The encrypted text as a Base64 string.</returns>
    /// <exception cref="ArgumentNullException">Thrown when plainText or publicKeyXml is null or empty.</exception>
    public static string Encrypt(string plainText, string publicKeyXml)
    {
        if (string.IsNullOrEmpty(plainText))
        {
            throw new ArgumentNullException(nameof(plainText), $"{nameof(plainText)} cannot be null");
        }

        if (string.IsNullOrEmpty(publicKeyXml))
        {
            throw new ArgumentNullException(nameof(publicKeyXml), $"{nameof(publicKeyXml)} cannot be null");
        }

        using var rsa = RSA.Create();
        rsa.FromXmlString(publicKeyXml);
        var data = System.Text.Encoding.UTF8.GetBytes(plainText);
        var encryptedData = rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA256);
        return Convert.ToBase64String(encryptedData);
    }

    /// <summary>
    /// Decrypts an encrypted string using RSA decryption with OAEP SHA-256 padding.
    /// </summary>
    /// <param name="encryptedText">The Base64 encoded encrypted text to decrypt.</param>
    /// <param name="privateKeyXml">The RSA private key in XML format.</param>
    /// <returns>The decrypted plain text.</returns>
    /// <exception cref="ArgumentNullException">Thrown when encryptedText or privateKeyXml is null or empty.</exception>
    public static string Decrypt(string encryptedText, string privateKeyXml)
    {
        if (string.IsNullOrEmpty(encryptedText))
        {
            throw new ArgumentNullException(nameof(encryptedText), $"{nameof(encryptedText)} cannot be null");
        }

        if (string.IsNullOrEmpty(privateKeyXml))
        {
            throw new ArgumentNullException(nameof(privateKeyXml), $"{nameof(privateKeyXml)} cannot be null");
        }

        using var rsa = RSA.Create();
        rsa.FromXmlString(privateKeyXml);
        var data = Convert.FromBase64String(encryptedText);
        var decryptedData = rsa.Decrypt(data, RSAEncryptionPadding.OaepSHA256);
        return System.Text.Encoding.UTF8.GetString(decryptedData);
    }
}
