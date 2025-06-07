namespace RsaEncryptionServiceUnitTests;

using FluentAssertions;
using RsaEncryptionService;
using System.Security.Cryptography;

public class EncryptionServiceTests
{
    private readonly RSA rsa;

    public EncryptionServiceTests()
    {
        this.rsa = RSA.Create(2048);
    }

    [Fact]
    public void CreateRsaKeys_ReturnsNonEmptyKeys()
    {
        var (publicKey, privateKey) = EncryptionService.CreateRsaKeys();

        Assert.False(string.IsNullOrWhiteSpace(publicKey));
        Assert.False(string.IsNullOrWhiteSpace(privateKey));
        Assert.NotEqual(publicKey, privateKey);
        Assert.Contains("<RSAKeyValue>", publicKey);
        Assert.Contains("<RSAKeyValue>", privateKey);
    }

    [Fact]
    public void CreateRsaKeys_KeysAreValidXml()
    {
        var (publicKey, privateKey) = EncryptionService.CreateRsaKeys();

        Assert.StartsWith("<RSAKeyValue>", publicKey);
        Assert.StartsWith("<RSAKeyValue>", privateKey);
        Assert.EndsWith("</RSAKeyValue>", publicKey);
        Assert.EndsWith("</RSAKeyValue>", privateKey);
    }

    [Fact]
    public void Encrypt_ReturnsString()
    {
        var actual = EncryptionService.Encrypt("Hello, World!", this.rsa.ToXmlString(false));

        _ = actual.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public void Decrypt_ReturnsCorrectString()
    {
        var publicKeyXml = this.rsa.ToXmlString(false);
        var privateKeyXml = this.rsa.ToXmlString(true);
        var encryptedText = EncryptionService.Encrypt("Hello, World!", publicKeyXml);

        var actual = EncryptionService.Decrypt(encryptedText, privateKeyXml);

        _ = actual.Should().NotBeNullOrEmpty();
        _ = actual.Should().Be("Hello, World!");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Encrypt_ThrowsArgumentNullException_WhenPlainTextIsNullOrEmpty(string? plainText)
    {
        var publicKeyXml = this.rsa.ToXmlString(false);

        var ex = Assert.Throws<ArgumentNullException>(() => EncryptionService.Encrypt(plainText!, publicKeyXml));
        Assert.Equal("plainText", ex.ParamName);
        Assert.Equal($"{nameof(plainText)} cannot be null (Parameter '{nameof(plainText)}')", ex.Message);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Encrypt_ThrowsArgumentNullException_WhenPublicKeyXmlIsNullOrEmpty(string? publicKeyXml)
    {
        var plainText = "test";

        var ex = Assert.Throws<ArgumentNullException>(() => EncryptionService.Encrypt(plainText, publicKeyXml!));
        Assert.Equal("publicKeyXml", ex.ParamName);
        Assert.Equal($"{nameof(publicKeyXml)} cannot be null (Parameter '{nameof(publicKeyXml)}')", ex.Message);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Decrypt_ThrowsArgumentNullException_WhenEncryptedTextIsNullOrEmpty(string? encryptedText)
    {
        var privateKeyXml = this.rsa.ToXmlString(true);

        var ex = Assert.Throws<ArgumentNullException>(() => EncryptionService.Decrypt(encryptedText!, privateKeyXml));
        Assert.Equal("encryptedText", ex.ParamName);
        Assert.Equal($"{nameof(encryptedText)} cannot be null (Parameter '{nameof(encryptedText)}')", ex.Message);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Decrypt_ThrowsArgumentNullException_WhenPrivateKeyXmlIsNullOrEmpty(string? privateKeyXml)
    {
        var encryptedText = "someBase64String";

        var ex = Assert.Throws<ArgumentNullException>(() => EncryptionService.Decrypt(encryptedText, privateKeyXml!));
        Assert.Equal("privateKeyXml", ex.ParamName);
        Assert.Equal($"{nameof(privateKeyXml)} cannot be null (Parameter '{nameof(privateKeyXml)}')", ex.Message);
    }

    [Fact]
    public void CreateRsaKeys_EncryptDecrypt_RoundTrip_Succeeds()
    {
        var (publicKey, privateKey) = EncryptionService.CreateRsaKeys();
        var originalText = "Hello, RSA Encryption!";

        var encrypted = EncryptionService.Encrypt(originalText, publicKey);
        var decrypted = EncryptionService.Decrypt(encrypted, privateKey);

        Assert.NotNull(publicKey);
        Assert.NotNull(privateKey);
        Assert.NotNull(encrypted);
        Assert.Equal(originalText, decrypted);
    }

    [Fact]
    public void Encrypt_WithInvalidPublicKey_ThrowsException()
    {
        var invalidPublicKey = "<RSAKeyValue></RSAKeyValue>";
        var plainText = "Test";

        var ex = Assert.ThrowsAny<CryptographicException>(() => EncryptionService.Encrypt(plainText, invalidPublicKey));
        Assert.Equal("Input string does not contain a valid encoding of the 'RSA' 'Modulus' parameter.", ex.Message);
    }

    [Fact]
    public void Decrypt_WithInvalidPrivateKey_ThrowsException()
    {
        var (publicKey, _) = EncryptionService.CreateRsaKeys();
        var plainText = "Test";
        var encrypted = EncryptionService.Encrypt(plainText, publicKey);
        var invalidPrivateKey = "<RSAKeyValue></RSAKeyValue>";

        var ex = Assert.ThrowsAny<CryptographicException>(() => EncryptionService.Decrypt(encrypted, invalidPrivateKey));
        Assert.Equal("Input string does not contain a valid encoding of the 'RSA' 'Modulus' parameter.", ex.Message);
    }
}
