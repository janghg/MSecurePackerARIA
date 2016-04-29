package co.msecure.util;

public class AndroidUtil {
	public static boolean isDexFile(String filepath) {
		String ext = filepath.substring(filepath.lastIndexOf(".")+1,filepath.length());
		if(!ext.equals("dex")) {
			return false;
		}
		return true;
	}
}
