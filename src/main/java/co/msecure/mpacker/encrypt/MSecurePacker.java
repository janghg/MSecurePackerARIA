package co.msecure.mpacker.encrypt;

import static org.junit.Assert.assertTrue;

import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.OutputStream;
import java.util.Calendar;
import java.util.Random;

import kr.re.nsri.aria.ARIAEngine;
import co.msecure.util.AndroidUtil;
import co.msecure.util.StringUtil;

public class MSecurePacker {
	public static void main(String[] args) throws Exception {
		MSecureARIAPacker packer = new MSecureARIAPacker();
		
		//Time stamp값 생성
	    Calendar cal = Calendar.getInstance( );
	    String timestamp = String.valueOf(Calendar.getInstance().getTime().getTime());
		
		// Random key create
		String text = "abcdef0123456789."; // 17개 , "."은 substring index때문에 넣음.
		String[] randomChar = new String[64];
		String randomKey = "";
		
		//arguments 
		String originFullPath = args[0];
		int selectEncDec = Integer.valueOf(args[1]);	// select encrypt or decrypt
		
		if(selectEncDec == 1) {
			for(int i=0; i<64; i++) {	// 32byte key 생성을 위함
				int randomIndex = (int) (Math.random() * 16);	// 0부터 15까지
				randomChar[i] = text.substring(randomIndex,randomIndex+1);
			}
		
			for (String s : randomChar) {	// key를 String형태로 저장
				randomKey += s;
			}
		}
		else if(selectEncDec == 2) {	// decrypt일때 키값 읽어오기 위함
			String keyFile = args[2];
			BufferedReader br = new BufferedReader(new FileReader(args[2]));
			randomKey = br.readLine();
		}
		
		if (args.length < 2) {
			System.err.println("[USAGE] [original dexfile path] [1:encryption or 2:decryption]");
			System.err.println("ex) \"a.dex\" 1");
			System.exit(1);
		} 
		

		File origin = new File(originFullPath);
		if (!origin.isFile()) {
			System.err.println("[ERROR] File is Unreachable");
			System.exit(1);
		}
		if(!AndroidUtil.isDexFile(originFullPath)) {
			System.err.println("[ERROR] input must be Dex File");
			System.exit(1);
		}
		// 256 bit ARIA engine
		packer.setARIAEngine(new ARIAEngine(256));
		byte[] key = StringUtil.toBytes(randomKey, 16);
	    packer.setKey(key);
		
		File f = new File(timestamp);
		if(!f.mkdirs()) {
			System.err.println("Directory creation fail");
		}
		
		//옵션줘서 encrypt , decrypt
		if (selectEncDec == 1) {
			String targetFullPath = timestamp + "/EncryptedClasses.dex";
			File target = new File(targetFullPath);	
			packer.encryptFileToFile(origin, target);		
			//packer.decryptFileToFile(target, new File(timestamp + "/b.txt"));
			
			//key값 출력
			BufferedWriter output = new BufferedWriter(new FileWriter(timestamp + "/key_value.txt"));
			output.write(randomKey);
			output.close();
		}
		
		else if (selectEncDec == 2) {
			String targetFullPath = timestamp + "/DecryptedClasses.dex";
			File target = new File(targetFullPath);			
			packer.decryptFileToFile(origin, target);
		}
	}
}
