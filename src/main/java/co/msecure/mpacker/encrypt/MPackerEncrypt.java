package co.msecure.mpacker.encrypt;

import java.io.BufferedInputStream;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class MPackerEncrypt {

	private static final String algorithm = "AES";
	private static final String transformation = algorithm + "/ECB/PKCS5Padding";
	
	private Key key;

	public MPackerEncrypt(Key key) {
		this.key = key;
	}
	
	public void encrypt(File source, File dest) throws Exception {
		crypt(Cipher.ENCRYPT_MODE, source, dest);
	}
	
	public void decrypt(File source, File dest) throws Exception {
		crypt(Cipher.DECRYPT_MODE, source, dest);
	}
	
	private void crypt(int mode, File source, File dest) throws Exception {
		Cipher cipher = Cipher.getInstance(transformation);
		cipher.init(mode, key);
		InputStream input = null;
		OutputStream output = null;
		try {
			input = new BufferedInputStream(new FileInputStream(source));
			output = new BufferedOutputStream(new FileOutputStream(dest));
			byte[] buffer = new byte[1024];
			int read = -1;
			while ((read = input.read(buffer)) != -1) {
				output.write(cipher.update(buffer, 0, read));
			}
			output.write(cipher.doFinal());
		} finally {
			if (output != null) {
				try { output.close(); } catch(IOException ie) {}
			}
			if (input != null) {
				try { input.close(); } catch(IOException ie) {}
			}
		}
	}
	
	public static boolean isDexFile(String filepath) {
		String ext = filepath.substring(filepath.lastIndexOf(".")+1,filepath.length());
		if(!ext.equals("dex")) {
			return false;
		}
		return true;
	}
	
	public static void main(String[] args) throws Exception {
		/*
		if (args.length < 2) {
			System.err.println("[USAGE] [original dexfile path]");
			System.exit(1);
		} 
		
		String originFullPath = args[0];
		String targetFullPath = args[1];
		File origin = new File(originFullPath);
		File target = new File(targetFullPath);
		
		if (!origin.isFile()) {
			System.err.println("[ERROR] File is Unreachable");
			System.exit(1);
		}
		
		if(!isDexFile(originFullPath)) {
			System.err.println("[ERROR] input must be Dex File");
			System.exit(1);
		}
				*/
		SecretKeySpec key = new SecretKeySpec(toBytes("696d697353796f7568616e6765656e6a", 16), algorithm);
		MPackerEncrypt coder = new MPackerEncrypt(key);
		//coder.encrypt(origin, target);

		//coder.decrypt(new File("D:/work/MPacker/vp0301/MispAndroid320_test_142/dist/MispAndroid320_test_142/m.png"), new File("D:/work/MPacker/vp0301/MispAndroid320_test_142/dist/MispAndroid320_test_142/classes_unpack"));
		coder.encrypt(new File("D:/work/MPacker/MSecurePackerTest/classes.dex"), new File("D:/work/MPacker/MSecurePackerTest/m.png"));
		coder.decrypt(new File("D:/work/MPacker/MSecurePackerTest/m.png"), new File("D:/work/MPacker/MSecurePackerTest/classes_unpack"));
	}
	
	public static byte[] toBytes(String digits, int radix) throws IllegalArgumentException, NumberFormatException {
		if (digits == null) {
			return null;
		}
		if (radix != 16 && radix != 10 && radix != 8) {
			throw new IllegalArgumentException("For input radix: \"" + radix + "\"");
		}
		int divLen = (radix == 16) ? 2 : 3;
    	int length = digits.length();
    	if (length % divLen == 1) {
    		throw new IllegalArgumentException("For input string: \"" + digits + "\"");
    	}
    	length = length / divLen;
    	byte[] bytes = new byte[length];
    	for (int i = 0; i < length; i++) {
    		int index = i * divLen;
    		bytes[i] = (byte)(Short.parseShort(digits.substring(index, index+divLen), radix));
    	}
    	return bytes;
	}
	

}