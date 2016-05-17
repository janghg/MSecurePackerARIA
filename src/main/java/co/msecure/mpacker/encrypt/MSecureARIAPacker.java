package co.msecure.mpacker.encrypt;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.util.Arrays;

import kr.re.nsri.aria.ARIAEngine;

import org.apache.commons.io.IOUtils;

public class MSecureARIAPacker {
	private ARIAEngine engine;
	
	public void setARIAEngine(ARIAEngine engine) {
		this.engine = engine;
	}
	
	public void setKey(byte[] key) {
		try {
			this.engine.setKey(key);
			this.engine.setupRoundKeys();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public void decryptStreamToFile(InputStream origin, File target) 
			throws InvalidKeyException, IOException {
		InputStream input = null;
		OutputStream output = null;
		try {
			input = new BufferedInputStream(origin);
			output = new BufferedOutputStream(new FileOutputStream(target));
			
			
			int bufferSize = 1024;	// 1KB
			int readLength;	// ���� Byte��
			byte[] buf = new byte[bufferSize];
			while((readLength = input.read(buf,0,bufferSize)) > 0) {	// ������ ������ �д´�.
				
				
				if(readLength == 16){	// ������ ���ڿ��� Byte���� 16Byte �϶�
					byte[] lastStringBuf = new byte[16];
					System.arraycopy(buf, 0, lastStringBuf, 0, readLength); // �о�� Byteũ�⸸ŭ �����Ѵ�.
					byte[] decrypted = this.decrypt(lastStringBuf, 0,readLength);	// ��ȣȭ �� ��
					decrypted = this.delPKC5Padding(decrypted);	// �е��� �����Ѵ�.
					output.write(decrypted);
					
				}
				else if(readLength < 1024){	// ������ ���ڿ��� Byte���� 1024Byte �̸� �϶�
					byte[] lastStringBuf = new byte[readLength];
					System.arraycopy(buf, 0, lastStringBuf, 0, readLength);
					byte[] decrypted = this.decrypt(lastStringBuf, 0, readLength);
					output.write(decrypted);
				}
				else{	// 1024Byte�� �о ��ȣȭ �Ѵ�.
					byte[] decrypted = this.decrypt(buf, 0, readLength);
					Arrays.fill(buf, (byte) 0);
					output.write(decrypted);
				}
				output.flush();
				
			}
		} finally {
			if (output != null) {
				try { output.close(); } catch(IOException ie) {}
			}
			if (input != null) {
				try { input.close(); } catch(IOException ie) {}
			}
		}
	}

	public void decryptFileToFile(File origin, File target) 
			throws InvalidKeyException, IOException {
		InputStream input = null;
		OutputStream output = null;
		try {
			input = new BufferedInputStream(new FileInputStream(origin));
			output = new BufferedOutputStream(new FileOutputStream(target));
			
			int bufferSize = 1024;	// 1KB
			int readLength;	// ���� Byte��
			byte[] buf = new byte[bufferSize];
			while((readLength = input.read(buf,0,bufferSize)) > 0) {	// ������ ������ �д´�.
				
				
				if(readLength == 16){	// ������ ���ڿ��� Byte���� 16Byte �϶�
					byte[] lastStringBuf = new byte[16];
					System.arraycopy(buf, 0, lastStringBuf, 0, readLength); // �о�� Byteũ�⸸ŭ �����Ѵ�.
					byte[] decrypted = this.decrypt(lastStringBuf, 0,readLength);	// ��ȣȭ �� ��
					decrypted = this.delPKC5Padding(decrypted);	// �е��� �����Ѵ�.
					output.write(decrypted);
					
				}
				else if(readLength < 1024){	// ������ ���ڿ��� Byte���� 1024Byte �̸� �϶�
					byte[] lastStringBuf = new byte[readLength];
					System.arraycopy(buf, 0, lastStringBuf, 0, readLength);
					byte[] decrypted = this.decrypt(lastStringBuf, 0, readLength);
					output.write(decrypted);
				}
				else{	// 1024Byte�� �о ��ȣȭ �Ѵ�.
					byte[] decrypted = this.decrypt(buf, 0, readLength);
					Arrays.fill(buf, (byte) 0);
					output.write(decrypted);
				}
				output.flush();
				
			}
			
		} finally {
			if (output != null) {
				try { output.close(); } catch(IOException ie) {}
			}
			if (input != null) {
				try { input.close(); } catch(IOException ie) {}
			}
		}
	}

	public void encryptStreamToFile(InputStream origin, File target) 
			throws InvalidKeyException, IOException {
		OutputStream output = null;
		InputStream input = null;
		try {
			input = new BufferedInputStream(origin);
			output = new BufferedOutputStream(new FileOutputStream(target));
			
			
			
			int bufferSize = 1024;	// 1KB
			int readLength;	// ���� Byte��
			byte[] buf = new byte[bufferSize];
			while((readLength = input.read(buf,0,bufferSize)) > 0) {	// ������ ������ �д´�.
				
				
				if(readLength <16){	// ������ ���ڿ��� Byte���� 16Byte �̸� �϶�
					byte[] lastStringBuf = new byte[16];
					System.arraycopy(buf, 0, lastStringBuf, 0, readLength); // �о�� Byteũ�⸸ŭ �����Ѵ�.
					byte[] bufferWithPadding = this.addPKC5Padding(lastStringBuf, 0, readLength);	// PKCS�е�
					byte[] encrypted = this.encrypt(bufferWithPadding, 0,readLength);
					output.write(encrypted);
					
				}
				else if(readLength < 1024){	// ������ ���ڿ��� Byte���� 1024Byte �̸� �϶�
					byte[] lastStringBuf = new byte[readLength];
					System.arraycopy(buf, 0, lastStringBuf, 0, readLength);
					byte[] encrypted = this.encrypt(lastStringBuf, 0, readLength);
					output.write(encrypted);
				}else{	// 1024Byte�� �о ��ȣȭ �Ѵ�.
					byte[] encrypted = this.encrypt(buf, 0, readLength);
					Arrays.fill(buf, (byte) 0);
					output.write(encrypted);
				}
				output.flush();
				
			}
			
		} finally {
			if (output != null) {
				try { output.close(); } catch(IOException ie) {}
			}
			if (input != null) {
				try { input.close(); } catch(IOException ie) {}
			}
		}
	}
	
	public void encryptFileToFile(File origin, File target) 
			throws InvalidKeyException, IOException {
		InputStream input = null;
		OutputStream output = null;
		try {
			input = new BufferedInputStream(new FileInputStream(origin));
			output = new BufferedOutputStream(new FileOutputStream(target));
			
			
			
			int bufferSize = 1024;	// 1KB
			int readLength;	// ���� Byte��
			byte[] buf = new byte[bufferSize];
			while((readLength = input.read(buf,0,bufferSize)) > 0) {	// ������ ������ �д´�.
				
				
				if(readLength <16){	// ������ ���ڿ��� Byte���� 16Byte �̸� �϶�
					byte[] lastStringBuf = new byte[16];
					System.arraycopy(buf, 0, lastStringBuf, 0, readLength); // �о�� Byteũ�⸸ŭ �����Ѵ�.
					byte[] bufferWithPadding = this.addPKC5Padding(lastStringBuf, 0, readLength);	// PKCS�е�
					byte[] encrypted = this.encrypt(bufferWithPadding, 0,readLength);
					output.write(encrypted);
					
				}
				else if(readLength < 1024){	// ������ ���ڿ��� Byte���� 1024Byte �̸� �϶�
					byte[] lastStringBuf = new byte[readLength];
					System.arraycopy(buf, 0, lastStringBuf, 0, readLength);
					byte[] encrypted = this.encrypt(lastStringBuf, 0, readLength);
					output.write(encrypted);
				}else{	// 1024Byte�� �о ��ȣȭ �Ѵ�.
					byte[] encrypted = this.encrypt(buf, 0, readLength);
					Arrays.fill(buf, (byte) 0);
					output.write(encrypted);
				}
				output.flush();
				
			}
			
		} finally {
			if (output != null) {
				try { output.close(); } catch(IOException ie) {}
			}
			if (input != null) {
				try { input.close(); } catch(IOException ie) {}
			}
		}
	}

	// PKCS5Padding  
	public byte[] addPKC5Padding(byte[] reqByte, int i, int read) throws InvalidKeyException {
		int paddingLength = reqByte.length - read;
		for(int idx=0;idx<paddingLength;idx++) {
			reqByte[read + idx] = (byte) paddingLength;
		}
		return reqByte;
	}
	
	public byte[] delPKC5Padding(byte[] decrypt) throws InvalidKeyException {
		for(int idx=decrypt.length, padding=0; idx > 0; idx--, padding++) {
			for(int end=decrypt.length, start = idx;
					start < end; start++) {
				if(!(Byte.toUnsignedInt(decrypt[start]) == padding)) {
					break;
				} else {
					byte[] result = new byte[decrypt.length - padding];
					for(int index=0; index < result.length;index++) {
						result[index] = decrypt[index];
					}
					return result;
				}
			}
		}
		return decrypt;
	}
	
	/**
	 * 16byte byte array encrypt to encrypted 16 byte array
	 * @param reqByte
	 * @return byte[] encrypted 16 byte array
	 * @throws InvalidKeyException
	 */
	public byte[] encryptDefault(byte[] reqByte) throws InvalidKeyException {
		return this.engine.encrypt(reqByte, 0);
	}
	
	public byte[] encrypt(byte[] reqByte, int i, int read) throws InvalidKeyException {
		if(reqByte.length > 16) {
			byte[] buffer = new byte[16];
			byte[] result = new byte[reqByte.length];
			for(int idx = 0, max = reqByte.length;idx < max; idx+=16) {
				int remain = reqByte.length - idx;
				if (!(remain < 16)) {
					System.arraycopy(reqByte, idx, buffer, 0, buffer.length);
					byte[] encrypted  = this.engine.encrypt(buffer, 0);
					System.arraycopy(encrypted, 0, result, idx, buffer.length);
				} else {
					buffer = new byte[16];
					// add space to result 
					result = Arrays.copyOf(result, result.length+(buffer.length - remain));
					// add PKCS5 Padding
					System.arraycopy(reqByte, idx, buffer, 0, remain);
					byte[] bufferWithPadding = this.addPKC5Padding(buffer, 0, remain);
					byte[] encrypted = this.engine.encrypt(bufferWithPadding, 0);
					System.arraycopy(encrypted, 0, result, idx, buffer.length);
				}
			}
			return result;
		} else {
			return this.engine.encrypt(reqByte, 0);
		}
	}
	
	/**
	 * 16byte byte array decrypt to decrypted 16 byte array
	 * @param reqByte	byte[] 16byte encrypted byte array
	 * @return byte[]	decrypted 16byte array
	 * @throws InvalidKeyException
	 */
	public byte[] decryptDefault(byte[] reqByte) throws InvalidKeyException {
		return this.engine.decrypt(reqByte, 0);
	}
	
	public byte[] decrypt(byte[] reqByte, int i, int read) throws InvalidKeyException {
		reqByte = Arrays.copyOfRange(reqByte, 0, read);
		
		if(reqByte.length > 16) {
			byte[] buffer = new byte[16];
			byte[] result = new byte[reqByte.length];
			for(int idx = 0, max = reqByte.length;idx < max; idx+=16) {
				System.arraycopy(reqByte, idx, buffer, 0, buffer.length);
				byte[] decrypted  = this.engine.decrypt(buffer, 0);
				System.arraycopy(decrypted, 0, result, idx, buffer.length);
			}
			
			System.arraycopy(result, result.length - buffer.length, buffer, 0, buffer.length);
			byte[] decrypted = this.delPKC5Padding(buffer);
			
			// remove padding
			int needToRemoveLength = buffer.length - decrypted.length;
			result = Arrays.copyOfRange(result, 0, result.length-needToRemoveLength);
			return result;
		} else {
			return this.engine.decrypt(reqByte, 0);
		}
	}
}
