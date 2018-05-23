package symmetric;

import org.junit.Assert;
import static org.junit.Assert.assertTrue;
import org.junit.Test;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class SymmetricKeyTest {

	@Test
	public void callingGenerateAESKey_shouldGenerateAESKey_throwNoException() {

		String algorithm = "AES";
		SecretKey key = null;

		try {
			key = SymmetricKey.generateKey(algorithm);
		} catch (Exception e) {
			Assert.fail("Should not have thrown an exception");
		}

		assertTrue(key.getAlgorithm().equals(algorithm));
		assertTrue(key instanceof SecretKey);
	}

	@Test
	public void callingGenerateAESKey_withInvalidAlgorithm_shouldthrowNoException() {

		String algorithm = "AESFRED";
		SecretKey key = null;

		try {
			key = SymmetricKey.generateKey(algorithm);
			Assert.fail("Should not reach here");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}

	}

	@Test
	public void callingGenerateEncryptingCipher_shouldGenerateCipher_throwNoException() {

		String algorithm = "AES";
		String provider = "SunJCE";
		SecretKey key = null;
		Cipher encryptingCipher = null;

		try {
			key = SymmetricKey.generateKey(algorithm);
			encryptingCipher = SymmetricKey.generateEncryptingCipher(key,algorithm);
		} catch (Exception e) {
			Assert.fail("Should not have thrown an exception");
		}

		assertTrue(key.getAlgorithm().equals(algorithm));
		assertTrue(key instanceof SecretKey);

		assertTrue(encryptingCipher.getAlgorithm().equals(algorithm));
		assertTrue(encryptingCipher instanceof Cipher);
		assertTrue(encryptingCipher.getProvider().getName().matches(provider));

	}

	@Test
	public void callingGenerateEncryptingCipher_shouldGenerateCipher_throwException()
			throws NoSuchAlgorithmException{

		String algorithm = "AESFRED";
		String provider = "SunJCE";
		SecretKey key = null;
		Cipher encryptingCipher = null;

		try {
			key = SymmetricKey.generateKey(algorithm);
			encryptingCipher = SymmetricKey.generateEncryptingCipher(key,algorithm);
			Assert.fail("Should not reach here");
		} catch (NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException e) {
			e.printStackTrace();
		}

	}


}
