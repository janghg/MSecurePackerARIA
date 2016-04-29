package co.msecure.util;


public class StringUtil {
	/**
	 * <p>���ڿ��� ����Ʈ�迭�� �ٲ۴�.</p>
	 * 
	 * @param digits ���ڿ�
	 * @param radix ����
	 * @return
	 * @throws IllegalArgumentException
	 * @throws NumberFormatException
	 */
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
	
	/**
	 * @param characters String be using when generate random string
	 * @param length int length of be generated string
	 * @return string random characteristic 
	 */
	public static String generateString(String characters, int length)
	{
	    char[] text = new char[length];
	    for (int i = 0; i < length; i++)
	    {
	    	int random = NumberUtil.getRandomIntBetween(0, characters.length());
	        text[i] = characters.charAt(random);
	    }
	    return new String(text);
	}
	
}
