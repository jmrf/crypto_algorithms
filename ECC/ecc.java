import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

public class ecc {
	

	/***************************************************
	 ***************** FUNC. AUXILIARES ****************
	 ***************************************************/
	
	private static BigInteger lambda(BigInteger[] P, BigInteger[] Q, BigInteger[] params){
		BigInteger lambda;
		// Si P == Q
		if (isEqual(P,Q,params[2])){
			lambda = ((new BigInteger("3")).multiply((P[0].pow(2)))).add(params[0]);					// 3*(x1)^2 +a
			lambda = lambda.multiply( ((new BigInteger("2")).multiply(P[1])).modInverse(params[2]));	// (2*y1)^(-1)
		}
		else {
			if (Q[0].subtract(P[0]) == BigInteger.ZERO){
				System.out.print("P:"); printPoint(P);
				System.out.print("Q:"); printPoint(Q);
			}
			BigInteger term2 = (Q[0].subtract(P[0])).modInverse(params[2]);							// EXPLOTA!!!!!
			lambda = (Q[1].subtract(P[1])).multiply(term2);												// (y2 - y1)*((x2-x1))^(-1)
		}
		return lambda;
	}

	/* devuelve cierto si el punto es infinito.
	   Valdria con comprobar que la tercera componente sea 0... */
	private static boolean isInf(BigInteger[] P){
		return P[2].equals(BigInteger.ZERO);
	}
	
	private static boolean isNeg(BigInteger[] P, BigInteger[] Q, BigInteger p){
			return P[0].equals(Q[0]) && P[1].equals(P[1].negate().mod(p));
	}
	
	private static boolean isEqual(BigInteger[] P, BigInteger[] Q, BigInteger p){
		return (P[0].equals(Q[0]) && P[1].mod(p).equals(Q[1].mod(p)) && P[2].equals(Q[2]));
	}
	
	private static BigInteger[] infinityPoint(){
		BigInteger inf[] = {BigInteger.ZERO,BigInteger.ONE,BigInteger.ZERO};
		return inf;
	}
	
	private static boolean inBetween(BigInteger k, BigInteger a, BigInteger b){
		return (k.compareTo(a) ==1) && (k.compareTo(b) == -1);
	}
	
	private static void printPoint(BigInteger[] P){
		if (isInf(P))
			System.out.println("Infinity");
		else{
			System.out.print("(");
			for (int i = 0; i < P.length; ++i){
				System.out.print(P[i]+" ");
			}
			System.out.println(")");
		}
	}
	
	
	/***************************************************
	 ***************** FUNC. PRINCIPALES ***************
	 ***************************************************/
	

	public static BigInteger[] invers(BigInteger[] P, BigInteger[] ParametresCorba){
		BigInteger[] inv = new BigInteger[3];
		if (isInf(P)) return P;
		if (!isInf(P)){
			inv[0] = P[0];
			inv[1] = P[1].negate();
            if (inv[1].compareTo(BigInteger.ZERO) == -1) 
            	inv[1] = inv[1].add(ParametresCorba[2]);
			inv[2] = P[2];
		}
		return inv;
	}
	
	/**
	 * 
	 * @param P
	 * @param Q
	 * @param ParametresCorba
	 * @return
	 */
	public static BigInteger [] suma( BigInteger [] P, BigInteger [] Q, BigInteger[] ParametresCorba){
		BigInteger p = ParametresCorba[2];
		BigInteger[] inf = {BigInteger.ZERO,BigInteger.ONE,BigInteger.ZERO};
		
		// si alguno es infinito...
		if (isInf(P)) return Q;
		if (isInf(Q)) return P;
		
		// si uno es inverso del otro...
		if (isEqual(P,invers(Q,ParametresCorba),p) ) 
			return inf;
		
		// Si no...
		else {
			BigInteger[] res = new BigInteger[3];
			BigInteger lambda = lambda(P, Q, ParametresCorba);
			res[0] = (((lambda.pow(2)).subtract(P[0])).subtract(Q[0])).mod(p);			// x' = lambda^2 - x1 - x2 mod(p) IMPORTANTE MODULO
			res[1] = (lambda.multiply(P[0].subtract(res[0])).subtract(P[1])).mod(p);	// lambda*(x1-x') - y1
			res[2] = BigInteger.ONE;
			return res;
		}
	}
	
	/**
	 * 
	 * @param k: entero
	 * @param P: P = (x,y,z) si z == 0 -> infinito
	 * @param ParametresCorba: {a,b,p}
	 * @return kP
	 */
	public static BigInteger[] multiple(BigInteger k, BigInteger [] P, BigInteger[] ParametresCorba){
		BigInteger res[] = new BigInteger[3];
		// R0 = Inf
		BigInteger R0[] = new BigInteger[3];
		R0[0] = BigInteger.ZERO; R0[1] = BigInteger.ONE; R0[2] = BigInteger.ZERO;
		// R1
		BigInteger R1[] = new BigInteger[3];
		// R1 = -P si k < 0
		if (k.compareTo(BigInteger.ZERO) == -1){
//			BigInteger invP[] = invers(P,ParametresCorba);
			R1[0] = P[0]; R1[1] = P[1].negate(); R1[2] = P[2];
		}
		// R1 = P si k >= 0	
		else{
			R1[0] = P[0]; R1[1] = P[1]; R1[2] = P[2];
		}
		
		byte[] bk = k.abs().toByteArray();
		int i = bk.length-1;
		
		// por si el ultimo bit es 1 y BigInteger añade un byte de 0s...
		int j = 0;
		while (bk[j] == 0x0) ++j;
		i = j;
		
		boolean primero = true;
			
		// algoritmo de Montgomery
		// Para todos los bytes...
		while (i < bk.length){
			for (int desp = 7; desp >= 0; --desp){
				int bit = ((bk[i] & (0x1 << desp)) >>> desp);
				if (bit == 0 && primero){}
				else{
					primero = false;
				
//					System.out.printf("%x ", bit);
					if (bit == 0){
						R1 = suma(R1,R0,ParametresCorba);
						R0 = suma(R0,R0,ParametresCorba);
					}
					else if (bit == 1){
						R0 = suma(R0,R1,ParametresCorba);
						R1 = suma(R1,R1,ParametresCorba);
					}
				}
			}
			++i;
		}
		return R0;
	}
	
	/**
	 * 
	 * @param parametresECC = {n,Gx,Gy,a,b,p}
	 * @return {r,Px,Py}
	 */
	public static BigInteger[] clausECC(BigInteger[] parametresECC){
		// result
		BigInteger keys[] = new BigInteger[3]; 
		
		//n 
		BigInteger n = parametresECC[0];
		
		// G
		BigInteger[] G = new BigInteger[3];
        G[0] = parametresECC[1];
        G[1] = parametresECC[2];
        G[2] = BigInteger.ONE;
        
        // parametresCorba: {a,b,p}
		BigInteger[] parametresCorba = new BigInteger[3];
		parametresCorba[0] = parametresECC[3];
		parametresCorba[1] = parametresECC[4];
		parametresCorba[2] = parametresECC[5];
		
		// r
		SecureRandom sRandom = new SecureRandom();
		byte rand[] = new byte[n.toByteArray().length];
		
		// P: punto aleatorio de la curva (clave publica)
		BigInteger[] P = infinityPoint();
		
		// Mientras P == infinito
		while (isInf(P)){
			sRandom.nextBytes(rand);
			BigInteger r = new BigInteger(1,rand);
			keys[0] = r.mod(n);
			if (inBetween(keys[0],BigInteger.ONE, n.subtract(BigInteger.ONE))) {
				// si 1 < r < (n-1)
				P = multiple(keys[0],G,parametresCorba);
				keys[1] = P[0]; 
				keys[2] = P[1];
			}
		}
		return keys;
	}
	
	/**
	 * 
	 * @param bytesAleatoris: lista de bytes aleatorios
	 * @param clauPrivadaECC: entero
	 * @param clauPublicaECC: P = (Px,Py) punto diferente de infinito
	 * @param parametresECC: {n,Gx,Gy,a,b,p}
	 * @return
	 */
	public static byte[] ECCDHKT(byte[] bytesAleatoris, BigInteger clauPrivadaECC,
			BigInteger[] clauPublicaECC, BigInteger[] parametresECC){
		
		// parametresCorba: {a,b,p}
		BigInteger[] parametresCorba = new BigInteger[3];
		parametresCorba[0] = parametresECC[3];
		parametresCorba[1] = parametresECC[4];
		parametresCorba[2] = parametresECC[5];
		
		// punto P
        BigInteger[] P = new BigInteger[3];
        P[0] = clauPublicaECC[0];
        P[1] = clauPublicaECC[1];
        P[2] = BigInteger.ONE;
        
        // Diffie Helman
        BigInteger[] DH_key = new BigInteger[3];
        DH_key = multiple(clauPrivadaECC, P, parametresCorba);
        byte[] x = DH_key[0].toByteArray();
        
        // por si el ultimo bit es 1 y BigInteger añade un byte de 0s...
 		int i = 0;
 		while (x[i] == 0) ++i;
     		
 		// concatenacion
        byte[] concat = new byte[bytesAleatoris.length + x.length - i];
        for (int j = 0; j < bytesAleatoris.length; ++j) concat[j] = bytesAleatoris[j];
        for (int j = bytesAleatoris.length; j < concat.length; ++j) concat[j] = x[j-bytesAleatoris.length+i];
        
        // calculo del hash
        byte k[] = sha512.hash(concat);
        return k;
	}
	
	/**
	 * 
	 * @param M: mensaje de longitud arbitraria
	 * @param clauFirma: clave privada del firmante (un entero)
	 * @param parametresECC: {n,Gx,Gy,a,b,p} (len(p) = 512 bits = 64 Bytes)
	 * @return: M || firma (firma de 2*len(p) = 128 Bytes)
	 */
	public static byte[] firmarECCDSA(byte[] M, BigInteger clauFirma, BigInteger[] parametresECC){
		//n 
		BigInteger n = parametresECC[0];
		
		// G
		BigInteger[] G = new BigInteger[3];
        G[0] = parametresECC[1];
        G[1] = parametresECC[2];
        G[2] = BigInteger.ONE;
        
        // parametresCorba: {a,b,p}
 		BigInteger[] parametresCorba = new BigInteger[3];
 		parametresCorba[0] = parametresECC[3];
 		parametresCorba[1] = parametresECC[4];
 		parametresCorba[2] = parametresECC[5];
 		
 		// k aleatorio
 		BigInteger k = BigInteger.ZERO;
 		SecureRandom sRandom = new SecureRandom();
		byte random[] = new byte[n.toByteArray().length];
		
		BigInteger f1 = BigInteger.ZERO;
		BigInteger f2 = BigInteger.ZERO;
		
		// si f1 == 0 ó f2 == 0 se genera un nuevo valor de k
		while (f1.compareTo(BigInteger.ZERO) == 0 || f2.compareTo(BigInteger.ZERO) == 0){
			sRandom.nextBytes(random);
			k = new BigInteger(1,random).mod(n);
			//  generamos k tq: 1 < k < (n-1)
			while (!inBetween(k,BigInteger.ONE, n.subtract(BigInteger.ONE))){
				sRandom.nextBytes(random);
				k = new BigInteger(1,random).mod(n);
			}
	 		BigInteger kG[] = multiple(k,G,parametresCorba);
	 		// f1 = (x_1) mod n
	 		f1 = kG[0].mod(n);
	 		//  f2 = k^(−1)*(H(M)+(f_1)*r) mod n
	 		f2 = k.modInverse(n).multiply(new BigInteger(1,sha512.hash(M)).add(f1.multiply(clauFirma))).mod(n);	
		}
		
//		System.out.println("\nf1:"+f1);
// 		System.out.println("f2:"+f2);

		byte bf1[] = f1.toByteArray();
		byte bf2[] = f2.toByteArray();
		
		byte ff1[] = new byte[64];
		byte ff2[] = new byte[64];
		
		// comprobando si BigInteger ha añadido 0s al principio
		if (bf1.length == 65)
			ff1 = Arrays.copyOfRange(bf1, 1, bf1.length);
		if (bf2.length == 65)
			ff2 = Arrays.copyOfRange(bf2, 1, bf2.length);
		
		// si no son lo suficientemente grandes añadimos 0s por detrás
		// bf1
		for (int i = 0; i < 64-bf1.length; ++i) ff1[i] = 0;
		for (int i = 0;i < bf1.length; ++i) ff1[64-bf1.length+i] = bf1[i];
		// bf2
		for (int i = 0; i < 64-bf2.length; ++i) ff2[i] = 0;
		for (int i = 0; i < bf2.length; ++i) ff2[64-bf2.length+i] = bf2[i];

		// firmamos: concatenemos mensaje con exactamente 128 bytes de firma
		byte res[] = new byte[M.length+128];
		for (int i = 0; i < M.length; ++i) res[i] = M[i];
		for (int i = 0; i < ff1.length; ++i) res[i+M.length] = ff1[i];
		for (int i = 0; i < ff2.length; ++i) res[i+M.length+ff1.length] = ff2[i];
		return res;
	}
	
	/**
	 * 
	 * @param MS: mensaje firmado con ECCDSA
	 * @param clauVer: firma publica del firmante
	 * @param parametresECC: parametros de la curva
	 * @return: cierto si es la firma es autentica, falso en otro caso
	 */
	public static boolean verificarECCDSA(byte[] MS, BigInteger[] clauVer, BigInteger[] parametresECC){
		//n 
		BigInteger n = parametresECC[0];
		
		// G
		BigInteger[] G = new BigInteger[3];
        G[0] = parametresECC[1];
        G[1] = parametresECC[2];
        G[2] = BigInteger.ONE;
        
        // P
        BigInteger[] P = new BigInteger[3];
        P[0] = clauVer[0];
        P[1] = clauVer[1];
        P[2] = BigInteger.ONE;
        
        // parametresCorba: {a,b,p} 
 		BigInteger[] parametresCorba = new BigInteger[3];
 		parametresCorba[0] = parametresECC[3];
 		parametresCorba[1] = parametresECC[4];
 		parametresCorba[2] = parametresECC[5];
 		
 		// f1,f2 y M
 		byte bf1[] = new byte[64];
 		byte bf2[] = new byte[64];
 		byte M[] = new byte[MS.length-128];
 		for (int i = 0; i < 64; ++i) bf2[64-i-1] = MS[MS.length-1-i];
 		for (int i = 0; i < 64; ++i) bf1[64-i-1] = MS[MS.length-64-1-i];
 		for (int i = 0; i < MS.length-128; ++i) M[i] = MS[i];
 		BigInteger f1 = new BigInteger(1,bf1);
 		BigInteger f2 = new BigInteger(1,bf2);
 		
 		// verificación
 		BigInteger w1 = (new BigInteger(1,sha512.hash(M))).multiply( f2.modInverse(n) );
 		BigInteger w2 = f1.multiply( f2.modInverse(n) ).mod(n);
 		BigInteger punto[] = suma(multiple(w1,G,parametresCorba),multiple(w2,P,parametresCorba),parametresCorba);
 		BigInteger x0 = punto[0];
// 		BigInteger y0 = punto[1];
 		
 		return (x0.mod(n).compareTo(f1) == 0);
	}
	
	
	
	
	/**
	 * MAIN
	 * @param args
	 */
	/*public static void main(String args[]){
		// curva
		BigInteger k = new BigInteger("32");
		BigInteger[] parametresCorba = new BigInteger[3];	// a,b,p
		parametresCorba[0] = BigInteger.ONE;
		parametresCorba[1] = BigInteger.ONE;
		parametresCorba[2] = new BigInteger("23");
		
		// punto P
		BigInteger [] P = new BigInteger[3];
		P[0] = new BigInteger("1179386930175642752037459333025490077436056970633746969029");
		P[1] = new BigInteger("-790269986949022244239866803091283107946136372908851322507");
		P[2] = new BigInteger("1");
		
		// punto Q
		BigInteger [] Q = new BigInteger[3];
		Q[0] = new BigInteger("5");
		Q[1] = new BigInteger("-7");
		Q[2] = new BigInteger("1");
		
		// parametros ECC
		BigInteger [] paramsECC = new BigInteger[6];
		paramsECC[0] = new BigInteger("23");		// orden
		paramsECC[1] = new BigInteger("17");		// Gx
		paramsECC[2] = new BigInteger("3");			// Gy
		paramsECC[3] = parametresCorba[0];			// a
		paramsECC[4] = parametresCorba[1];			// b
		paramsECC[5] = parametresCorba[2];			// p

		System.out.print("inverso: "); printPoint(invers(P, parametresCorba));
		System.out.print("suma: ") ;printPoint(suma(P,P, parametresCorba));
		//printPoint(invers(P,parametresCorba));
//		printPoint(multiple(k, P, parametresCorba));
		

	}*/
}
