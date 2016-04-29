package encrypt;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.util.Arrays;

import kr.re.nsri.aria.ARIAEngine;

import org.apache.commons.io.IOUtils;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

import co.msecure.mpacker.encrypt.MPackerEncrypt;
import co.msecure.mpacker.encrypt.MSecureARIAPacker;
import co.msecure.util.NumberUtil;
import co.msecure.util.StringUtil;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class MSecureARIAPackerTest {
	MSecureARIAPacker packer;
	public String text = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()[]<>?";
	public MSecureARIAPackerTest() {	// ARIA 암호키 생성
		packer = new MSecureARIAPacker();
		try {
			packer.setARIAEngine(new ARIAEngine(256));
			byte[] key = StringUtil.toBytes("696d697353796f7568616e6765656e6a696d697353796f7568616e6765656e6a", 16);
			packer.setKey(key);
		} catch (InvalidKeyException e) {
			fail("Packer Create Fail");
		}
	}
	
	@Test
	public void firstTestFileToFile() {
		File src = new File("src_test.txt");
		File encryptedFile = new File("encrypted_test.txt");
		File decryptedFile = new File("decrypted_test.txt");
		
		for(int i=0;i<100;i++) {
			/*
			if(i== 250) {
				System.out.println(i);
			}
			*/
			String rndString = StringUtil.generateString(text, NumberUtil.getRandomIntBetween(0, 999999));
			OutputStream output = null;
			try {
				
				
				output = new BufferedOutputStream(new FileOutputStream(src));
				byte[] writing = rndString.getBytes();
				output.write(writing, 0, writing.length);
				output.flush();
				output.close();
				output = null;
				
				
			} catch (FileNotFoundException e) {
				e.printStackTrace();
			} catch (IOException e) {
				
			} finally {
				if (output != null) {
					try { output.close(); } catch(IOException ie) {}
				}
			}
			try {
				packer.encryptFileToFile(src, encryptedFile);
				
				try {
					//create object of BufferedInputStream
			        BufferedInputStream bin = new BufferedInputStream(new FileInputStream(encryptedFile));
			        
			        
			        
			        Long size = encryptedFile.length();
			        byte[] file = IOUtils.toByteArray(bin);
			        byte[] decrypted = packer.decrypt(file, 0, file.length);
			        
			        String decryptedString = new String(decrypted, 0, decrypted.length);
			        //System.out.println(decryptedString.replace(rndString, ""));
			        assertEquals(rndString, new String(decrypted, 0, decrypted.length));
			        
			        bin.close();
				} catch (IOException e) {
					fail("check");
				} finally {
					
				}
			} catch (InvalidKeyException | IOException e) {
				fail("encryptFileToFile");
			}
			
			try {	
				packer.decryptFileToFile(encryptedFile, decryptedFile);
				
				//create object of BufferedInputStream
		        BufferedInputStream bin = new BufferedInputStream(new FileInputStream(decryptedFile));
		        byte[] file = IOUtils.toByteArray(bin);
		        
		        String decryptedString = new String(file, 0, file.length);
		        //System.out.println(decryptedString.replace(rndString, ""));
		        assertEquals(rndString, decryptedString);
		        
		        bin.close();
			} catch (IOException e) {
				fail("check");
			} catch (InvalidKeyException e) {
				fail("InvalidKeyException");
			} finally {
				
			}
		}
			
		assertTrue(src.isFile() && encryptedFile.isFile());
	}
	
	@Test
	public void secondTestBigFile() {
		File src = new File("src_test.txt");
		File encryptedFile = new File("encrypted_test.txt");
		File decryptedFile = new File("decrypted_test.txt");
		
		String rndString = StringUtil.generateString(text, 99999999);
		OutputStream output = null;
		try {
			output = new BufferedOutputStream(new FileOutputStream(src));
			byte[] writing = rndString.getBytes();
			output.write(writing, 0, writing.length);
			output.flush();
			output.close();
			output = null;
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			
		} finally {
			if (output != null) {
				try { output.close(); } catch(IOException ie) {}
			}
		}
		try {
			packer.encryptFileToFile(src, encryptedFile);
			
			try {
				//create object of BufferedInputStream
		        BufferedInputStream bin = new BufferedInputStream(new FileInputStream(encryptedFile));
		        
		        Long size = encryptedFile.length();
		        byte[] file = IOUtils.toByteArray(bin);
		        byte[] decrypted = packer.decrypt(file, 0, file.length);
		        
		        String decryptedString = new String(decrypted, 0, decrypted.length);
		        //System.out.println(decryptedString.replace(rndString, ""));
		        assertEquals(rndString, new String(decrypted, 0, decrypted.length));
		        
		        bin.close();
			} catch (IOException e) {
				fail("check");
			} finally {
				
			}
		} catch (InvalidKeyException | IOException e) {
			fail("encryptFileToFile");
		}
		
		try {
			packer.decryptFileToFile(encryptedFile, decryptedFile);
			
			//create object of BufferedInputStream
	        BufferedInputStream bin = new BufferedInputStream(new FileInputStream(decryptedFile));
	        byte[] file = IOUtils.toByteArray(bin);
	        
	        String decryptedString = new String(file, 0, file.length);
	        //System.out.println(decryptedString.replace(rndString, ""));
	        assertEquals(rndString, decryptedString);
	        
	        bin.close();
		} catch (IOException e) {
			fail("check");
		} catch (InvalidKeyException e) {
			fail("InvalidKeyException");
		} finally {
			
		}
		
			
		assertTrue(src.isFile() && encryptedFile.isFile());
	}
	
	
	@Test
	public void testEncrypteCorrectDefault() {
		try {
			for(int i=1;i<1000;i++) {
				String rndString = StringUtil.generateString(text, 16);
				byte[] originStringByteArray = rndString.getBytes();
				byte[] encrypted = packer.encryptDefault(originStringByteArray);
				byte[] decrypted = packer.decryptDefault(encrypted);
				assertTrue(Arrays.equals(originStringByteArray, decrypted));
			}
		} catch (InvalidKeyException e) {
			fail("InvalidKeyException");
		}
	}
	
	@Test
	public void testEncryptCorrectBig() {
		try {
			String rndString = StringUtil.generateString(text, 32);
			byte[] originStringByteArray = rndString.getBytes();
			byte[] encrypted = packer.encrypt(originStringByteArray, 0, 32);
			byte[] decrypted = packer.decrypt(encrypted, 0, encrypted.length);
			assertTrue(Arrays.equals(originStringByteArray, decrypted));
			for(int i=1;i<100;i++) {
				rndString = StringUtil.generateString(text, NumberUtil.getRandomIntBetween(0, 999999));
				originStringByteArray = rndString.getBytes();
				encrypted = packer.encrypt(originStringByteArray, 0, originStringByteArray.length);
				decrypted = packer.decrypt(encrypted, 0, encrypted.length);
				assertTrue(Arrays.equals(originStringByteArray, decrypted));
			}
		} catch (InvalidKeyException e) {
			fail("InvalidKeyException");
		}
	}
	
	@Test
	public void testIsDexFile() {
		// true case
		String fileName = "thisisTrue.dex";
		assertTrue(MPackerEncrypt.isDexFile(fileName));
		fileName = "dex.!(@*$(&%_!(_@)#(&%(!@#*.dex";
		assertTrue(MPackerEncrypt.isDexFile(fileName));
		
		// false case 
		fileName = "nevereverTrue.dex.dex.not";
		assertFalse(MPackerEncrypt.isDexFile(fileName));
		fileName = "dex.dex.dex.dex.dex.de.x";
		assertFalse(MPackerEncrypt.isDexFile(fileName));
		fileName = "dex.!(@*$(&%_!(_@)#(&%(!@#*.de(^!@(#*x";
		assertFalse(MPackerEncrypt.isDexFile(fileName));
		fileName = "dex.!(@*$(&%_!(_@)#(&%(!@#*.de x";
		assertFalse(MPackerEncrypt.isDexFile(fileName));
	}
	
	@Test
	public void testAddPKC5Padding() {
		byte[] testTrue = new byte[16];
		testTrue[0] = 10; testTrue[1] = 10; testTrue[2] = 10; testTrue[3] = 10;
		byte[] expected = new byte[]{10, 10, 10, 10, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12};
		
		try {
			byte[] result = packer.addPKC5Padding(testTrue, 0, 4);
			assertTrue(Arrays.equals(result, expected));
		} catch (InvalidKeyException e) {
			fail("this is not normal");
		}
	}
	
	@Test
	public void testDelPKC5Padding() {
		byte[] paddingValue = new byte[]{10, 10, 10, 10, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12};
		byte[] expected = new byte[4];
		expected[0] = 10; expected[1] = 10; expected[2] = 10; expected[3] = 10;
		
		try {
			byte[] result = packer.delPKC5Padding(paddingValue);
			assertTrue(Arrays.equals(result, expected));
		} catch (InvalidKeyException e) {
			fail("this is not normal");
		}
	}
		
}
