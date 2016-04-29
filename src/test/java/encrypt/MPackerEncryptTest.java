package encrypt;

import static org.junit.Assert.*;
import org.junit.Test;
import co.msecure.mpacker.encrypt.MPackerEncrypt;

public class MPackerEncryptTest {
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
}
