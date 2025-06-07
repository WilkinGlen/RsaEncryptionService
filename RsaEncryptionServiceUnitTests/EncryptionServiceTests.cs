namespace RsaEncryptionServiceUnitTests;

using FluentAssertions;
using RsaEncryptionService;
using System.Security.Cryptography;

/// <summary>
/// Contains unit tests for the RSA encryption and decryption functionality.
/// </summary>
public class EncryptionServiceTests
{
    private readonly RSA rsa;

    /// <summary>
    /// Initializes a new instance of the <see cref="EncryptionServiceTests"/> class.
    /// </summary>
    public EncryptionServiceTests()
    {
        this.rsa = RSA.Create(2048);
    }

    /// <summary>
    /// Verifies that CreateRsaKeys generates non-empty public and private keys in valid XML format.
    /// </summary>
    [Fact]
    public void CreateRsaKeys_ReturnsNonEmptyKeys()
    {
        var (publicKey, privateKey) = EncryptionService.CreateRsaKeys();

        Assert.False(string.IsNullOrWhiteSpace(publicKey));
        Assert.False(string.IsNullOrWhiteSpace(privateKey));
        Assert.NotEqual(publicKey, privateKey);
        Assert.StartsWith("<RSAKeyValue>", publicKey);
        Assert.StartsWith("<RSAKeyValue>", privateKey);
        Assert.EndsWith("</RSAKeyValue>", publicKey);
        Assert.EndsWith("</RSAKeyValue>", privateKey);
    }

    /// <summary>
    /// Verifies that generated RSA keys are in valid XML format with correct start and end tags.
    /// </summary>
    [Fact]
    public void CreateRsaKeys_KeysAreValidXml()
    {
        var (publicKey, privateKey) = EncryptionService.CreateRsaKeys();

        Assert.StartsWith("<RSAKeyValue>", publicKey);
        Assert.StartsWith("<RSAKeyValue>", privateKey);
        Assert.EndsWith("</RSAKeyValue>", publicKey);
        Assert.EndsWith("</RSAKeyValue>", privateKey);
    }

    /// <summary>
    /// Verifies that the Encrypt method returns a non-empty string when given valid input.
    /// </summary>
    [Fact]
    public void Encrypt_ReturnsString()
    {
        var actual = EncryptionService.Encrypt("Hello, World!", this.rsa.ToXmlString(false));

        _ = actual.Should().NotBeNullOrEmpty();
    }

    /// <summary>
    /// Verifies that the Decrypt method correctly decrypts previously encrypted text.
    /// </summary>
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

    /// <summary>
    /// Verifies that Encrypt throws ArgumentNullException when plainText is null or empty.
    /// </summary>
    /// <param name="plainText">The plain text input to test.</param>
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

    /// <summary>
    /// Verifies that Encrypt throws ArgumentNullException when publicKeyXml is null or empty.
    /// </summary>
    /// <param name="publicKeyXml">The public key XML string to test.</param>
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

    /// <summary>
    /// Verifies that Decrypt throws ArgumentNullException when encryptedText is null or empty.
    /// </summary>
    /// <param name="encryptedText">The encrypted text to test.</param>
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

    /// <summary>
    /// Verifies that Decrypt throws ArgumentNullException when privateKeyXml is null or empty.
    /// </summary>
    /// <param name="privateKeyXml">The private key XML string to test.</param>
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

    /// <summary>
    /// Verifies that a complete encryption and decryption round-trip succeeds using generated keys.
    /// </summary>
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

    /// <summary>
    /// Verifies that Encrypt throws CryptographicException when provided with an invalid public key.
    /// </summary>
    [Fact]
    public void Encrypt_WithInvalidPublicKey_ThrowsException()
    {
        var invalidPublicKey = "<RSAKeyValue></RSAKeyValue>";
        var plainText = "Test";

        var ex = Assert.ThrowsAny<CryptographicException>(() => EncryptionService.Encrypt(plainText, invalidPublicKey));
        Assert.Equal("Input string does not contain a valid encoding of the 'RSA' 'Modulus' parameter.", ex.Message);
    }

    /// <summary>
    /// Verifies that Decrypt throws CryptographicException when provided with an invalid private key.
    /// </summary>
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
