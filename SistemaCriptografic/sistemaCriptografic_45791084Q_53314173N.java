import java.math.BigInteger;
import java.security.SecureRandom;

/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author roger.catala.abenza
 */
public class sistemaCriptografic {
	
	public static byte[] enviarMissatge(byte[] M, BigInteger clauDeFirma, BigInteger clauPrivadaECC,
			BigInteger[] clauPublicaECC, BigInteger[] parametresECC){
		
		// mensaje con firma
		byte[] mf = ecc.firmarECCDSA(M, clauDeFirma, parametresECC);
		
		SecureRandom sRandom = new SecureRandom();
		byte KSE[] = new byte[64];
		sRandom.nextBytes(KSE);
		
		// generamos la clave para el AES (clave de sesión)
		byte KS_temp[] = ecc.ECCDHKT(KSE, clauPrivadaECC, clauPublicaECC, parametresECC);
		
		// nos quedamos con los 256 primeros bytes
		byte KS[] = new byte[32];
		for (int i = 0; i < 32; ++i) KS[i] = KS_temp[i];
		
		// ciframos con AES
		byte emf[] = aes.xifrarAES(mf, KS);
		
		// concat de KSE y emf
		byte C[] = new byte[KSE.length + emf.length];
		for (int i = 0; i < KSE.length; ++i) C[i] = KSE[i];
		for (int i = KSE.length; i < C.length; ++i) C[i] = emf[i-KSE.length];
		
		return C;
	}
	
	
	
	
	
	public static byte [ ] rebreMissatge(byte[] C, BigInteger[] clauDeVerificacioDeFirma,
			BigInteger clauPrivadaECC, BigInteger[] clauPublicaECC,
			BigInteger[] parametresECC){
		
		// split del criptograma
		byte KSE[] = new byte[64];
		byte emf[] = new byte[C.length-64];
		for (int i = 0; i < 64; ++i) KSE[i] = C[i];
		for (int i = 64; i < C.length; ++i) emf[i-64] = C[i];
		
		// recuperar KS
		// generamos la clave para el AES (clave de sesión)
		byte KS_temp[] = ecc.ECCDHKT(KSE, clauPrivadaECC, clauPublicaECC, parametresECC);
		
		// nos quedamos con los 256 primeros bytes
		byte KS[] = new byte[32];
		for (int i = 0; i < 32; ++i) KS[i] = KS_temp[i];
		
		// mensaje y firma
		byte mf[] = aes.desxifrarAES(emf, KS);
		
		// verificamos la firma
		boolean v = ecc.verificarECCDSA(mf, clauDeVerificacioDeFirma, parametresECC);
		
		byte mv[] = new byte[mf.length+1];
		for (int i = 0; i < mf.length; ++i) mv[i] = mf[i];
		if (!v) mv[mv.length-1] = (byte) 0xff;
		
		return mv;
	}
    
}
