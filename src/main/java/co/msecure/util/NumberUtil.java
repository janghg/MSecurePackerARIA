package co.msecure.util;

import java.util.Random;

public class NumberUtil {
	public static int getRandomIntBetween(int min, int max) {
		Random random = new Random();
		return random.nextInt(max - min) + min;
	}
	
	public static boolean isAlign(int arg, int align) {
		if (arg % align > 0) {
			return false;
		}
		return true;
	}
}
