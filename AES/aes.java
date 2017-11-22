import java.math.BigInteger;
import java.util.Random;
import java.util.Scanner;

/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author jose.marcos.rodriguez
 */


public class aes{

	private static byte[] GF;
	private static int[] log;
    private static int Nk;
    private static int Nr;
    
    private static byte[][] Rcon = {
    	{(byte)0x01, (byte)0x02,(byte) 0x04, (byte)0x08,(byte) 0x10,(byte) 0x20,(byte) 0x40,(byte) 0x80,(byte) 0x1b,(byte) 0x36,(byte) 0x15,(byte) 0x6c,(byte) 0xd8,(byte) 0xab,(byte) 0x4d},
        {(byte)0x00, (byte)0x00,(byte) 0x00, (byte)0x00,(byte) 0x00,(byte) 0x00,(byte) 0x00,(byte) 0x00,(byte) 0x00,(byte) 0x00,(byte) 0x00,(byte) 0x00,(byte) 0x00,(byte) 0x00,(byte) 0x00},
        {(byte)0x00, (byte)0x00,(byte) 0x00, (byte)0x00,(byte) 0x00,(byte) 0x00,(byte) 0x00,(byte) 0x00,(byte) 0x00,(byte) 0x00,(byte) 0x00,(byte) 0x00,(byte) 0x00,(byte) 0x00,(byte) 0x00},
        {(byte)0x00, (byte)0x00,(byte) 0x00, (byte)0x00,(byte) 0x00,(byte) 0x00,(byte) 0x00,(byte) 0x00,(byte) 0x00,(byte) 0x00,(byte) 0x00,(byte) 0x00,(byte) 0x00,(byte) 0x00,(byte) 0x00}
        };
    
    
    
    
	
	/***************************************************
	 ************ FUNC. AUX Y GENERADORAS **************
	 ***************************************************/
	
	private static byte[] generaGF(){
		byte[] gf = new byte[255];
        gf[0] = 0x01;
		gf[1] = 0x03;                                                   // pol. generador (atento indice maximo)
        for (int i = 2; i < 255; ++i) {
            byte temp = (byte)(gf[i-1] << 1);                           // multiplicamos por X
            if ((gf[i-1] & 0x80) == 0x80) temp = (byte) (temp ^ 0x1B);	// solo si nos pasamos de grado
            gf[i] = suma(temp,gf[i-1]);                                 // sumamos el polinomio original
        }
        return gf;
	}
	
	
	private static int[] logGF(byte[] gf){
            int log[] = new int[256];
            int index;
            for (int i = 0; i < 255; ++i){
                index = (int) (gf[i] + 256) % 256;
                log[index] = i;
            }
            return log;
	}
	
	
	private static byte suma(byte a, byte b){
            return (byte) (a ^ b);
	}
	
	
	private static byte mult(byte a, byte b) {
        if(a == 0x00 || b == 0x00) 
            return 0x00;
        else{
            int ind1 = log[(a + 256) % 256];
            int ind2 = log[(b + 256) % 256];
            return GF[((ind1+ind2) % 255)];		// (g^1)*(g^j) = g^(i+j)
        }
    }

	
	private static byte inverso(byte a) {
        if (a == 0 || a == 1) return a;
        else{
        	int ind = log[(a + 256) % 256];
        	ind = (ind + 256) % 256;
        	return GF[255 - ind];
        }
    }
    
    // padding del sha512...
    private static byte[] padMessage(byte[] M){
		int l = M.length;
		int lInBits = l*8;
		int n = (int) Math.ceil((double)(lInBits+8+128)/1024.0f);
		int k = (n*1024-lInBits-1)/8;	// k = bytes to append
		byte[] m = new byte[l+1+k];
		// padding
		for (int i = 0; i < l; ++i)
			m[i] = M[i];
		// appending 1
		m[l] = (byte) 0x80L;
		// appending 0's
		for (int i = 0; i < k; ++i){
			m[l+1+i] = (byte) 0x00L;
		}
		// adding original size info
		// we suppose it fits in a long (64 bits)
		for (int i = 0; i < 8; ++i){
			m[l+k-i] = (byte) (lInBits & 0xFF);
			lInBits = lInBits >> 8;
		}
		return m;
	}
	
	private static byte[] quitaPadding(byte[] a) {
        int tam = 0;
        for (int i = 7; i >= 0; --i) {
            tam = tam << 8;
            tam = tam | (a[a.length - 1 -i]& 0x00FF);
        }
        tam = tam/8;
        if (tam < 0) tam = tam + 32;
        byte[] m = new byte[tam];
        for (int i = 0; i < m.length; ++i) m[i] = a[i];
        return m;
    }
	
	
	/*
	 * Transforms the message in a 4 by 4 matrix called state
	 */
	private static byte[][] createState(byte[] msg){
		byte[][] s = new byte[4][4];
		int i = 0;
		for (int c = 0; c < 4; ++c){
            for (int f = 0; f < 4; ++f){
                s[f][c] = msg[i];
                ++i;
            }
		}
		return s;
	}
	
	
    /*
     * Transforms the key in a 4 by 4 matrix
     */
    private static byte[][] createKey(byte[] key){
        Nk = (key.length*8)/32;
        Nr = Nk+6;
        byte[][] k = new byte[4][Nk];
        int i = 0;
        for (int c = 0; c < Nk; ++c){
            for (int f = 0; f < 4; ++f){
                k[f][c] = key[i];
                ++i;
            }
        }
        return k;
    }
   
    
    private static byte[] shiftRowLeft(byte[] row,int desp){
        desp = desp % row.length;
        if (desp == 0) return row;
        else {
            byte[] res = row.clone();
            // desplazamos todos a la izquierda
            for (int i = 0; i < row.length-desp; ++i){
                res[i] = row[i+desp];
            }
            // copiamos lo que se sale de la fila
            desp = row.length-desp;
            for (int i = desp; i < row.length; ++i){
                res[i] = row[i-desp];
            }
            return res;
        }
    }
    
    
    private static byte[] shiftRowRight(byte[] row,int desp){
        desp = desp % row.length;
    	if (desp == 0) return row;
        else {
            byte[] res = row.clone();
            // desplazamos todos a laderecha
            for (int i = 0; i < row.length-desp; ++i){
                res[i+desp] = row[i];
            }
            // copiamos lo que se sale de la fila
            desp = row.length-desp;
            for (int i = desp; i < row.length; ++i){
                res[i-desp] = row[i];
            }
            return res;
        }
    }
    
    
    /*
     * Java convierte antes de hacer un shift el byte a un int
     * por eso hay que hacer primero un AND con 0xFF al hacer >>>
     */
    private static byte rotL(byte b, int n){
		int w = 8-n;
		return (byte) ((b << n) | ((b & 0x00FF) >>> w));
	}

	
    
	
	/***************************************************
	 ***************** AES FUNCTIONS *******************
	 ***************************************************/

    
	public static void init(){
		GF = generaGF();
		log = logGF(GF);
	}
	

	public static byte[][][] keyExpansion(byte[] k){
		byte [][] K = createKey(k);
		byte [][] W = new byte[4][4*(Nr+1)];
		
		// copy the original key at the beginning:
		for (int c = 0; c < Nk; ++c){
			for (int f = 0; f < 4; ++f){
				W[f][c] = K[f][c];
			}
		}
		
		// expanding:
		for (int i = Nk; i < 4*(Nr+1); ++i){
			byte [] temp = new byte[4];
			
			// copy temporal sub key
			for(int j = 0; j < 4; ++j) 
				temp[j] = W[j][i-1];
			
			// Applying transf. depending on column
			if (i % Nk == 0){
				// rotWord
				byte last = temp[0];
				temp[0] = temp[1];
				temp[1] = temp[2];
				temp[2] = temp[3];
				temp[3] = last;
				
				// byteSub
				for (int l = 0; l < 4; ++l) temp[l] = (byte) (byteSub(temp[l]) ^ Rcon[l][(i / Nk) -1]);
			}
			if ((Nk == 8) && (i % Nk == 4)){
				for (int l = 0; l < 4; ++l) temp[l] = byteSub(temp[l]);
			}
			// updating W
			for(int l = 0; l < 4; ++l) W[l][i] = (byte) (W[l][i-Nk] ^ temp[l]);
			
		}
		// Transforming the result as a vector of bloc keys
		byte[][][] res = new byte[Nr+1][4][4];
         for (int i = 0; i < 4*(Nr+1); ++i) {
             for (int j = 0; j < 4; ++j) res[i/4][j][i%4] = W[j][i];
         }
         return res;
	}
	
	
	public static byte byteSub(byte subestat){
        byte b;
        if (subestat != 0)
          b = (byte) inverso(subestat);
        else 
          b = subestat;

        return (byte) (b ^ rotL(b, 4) ^ rotL(b, 3) ^ rotL(b, 2) ^ rotL(b, 1) ^ 0x63);

	}
	
	
	public static byte[][] shiftRow(byte[][] estat){
		byte[][] temp = new byte[4][4];
        for (int i = 0; i < 4; ++i){
          temp[i] = shiftRowLeft(estat[i],i);
        }
        return temp;
	}
	
	
	public static byte[][] mixColumn(byte[][] estat){
		byte[][] w = new byte[4][4];
        for (int i = 0; i < estat.length; ++i) {
            w[0][i] = (byte) (mult(estat[0][i], (byte)0x02) ^ mult(estat[1][i], (byte)0x03) ^ estat[2][i] ^ estat[3][i]);
            w[1][i] = (byte) (mult(estat[1][i], (byte)0x02) ^ mult(estat[2][i], (byte)0x03) ^ estat[0][i] ^ estat[3][i]);
            w[2][i] = (byte) (mult(estat[2][i], (byte)0x02) ^ mult(estat[3][i], (byte)0x03) ^ estat[0][i] ^ estat[1][i]);
            w[3][i] = (byte) (mult(estat[3][i], (byte)0x02) ^ mult(estat[0][i], (byte)0x03) ^ estat[2][i] ^ estat[1][i]);
        }
        return w;
	}
	
	
	public static byte[][] addRoundKey(byte[][] estat, byte[][] Ki){
		byte[][] res = new byte[4][4];
        for (int i = 0; i < 4; ++i){
            for (int j = 0; j < 4; ++j){
                res[i][j] = (byte) (estat[i][j] ^ Ki[i][j]);
            }
        }
        return res;
	}
	
	
	
	
	/***************************************************
	 ***************** FUNC. INVERSAS ******************
	 ***************************************************/
	
	
	public static byte[][][] invKeyExpansion(byte[] k){
		byte [][][] W = keyExpansion(k);
		for (int i = 1; i < Nr; ++i) 
			W[i] = invMixColumn(W[i]);
		return W;
	}
	
	
	public static byte invByteSub(byte subestat){
		byte b = (byte) (subestat ^ 0x63);
		b = (byte) (rotL(b, 1) ^ rotL (b, 6) ^ rotL(b, 3));		// inversa de la transformación afín
        if (b != 0x00) 
        	b = inverso(b);
		return b;
	}
	
	
	public static byte[][] invShiftRow(byte[][] estat){
		byte[][] temp = new byte[4][4];
	    for (int i = 0; i < 4; ++i){
	        temp[i] = shiftRowRight(estat[i],i);
	      }
		return temp;
	}
	
	
	public static byte[][] invMixColumnMINE(byte[][] estat){
		byte[][] w = new byte[4][4];
        for (int i = 0; i < estat.length; ++i) {
            w[0][i] = (byte) (mult(estat[0][i], (byte)0x0E) ^ mult(estat[1][i], (byte)0x0B) ^ mult(estat[2][i], (byte)0x0D) ^ mult(estat[3][i],(byte)0x09));
            w[1][i] = (byte) (mult(estat[1][i], (byte)0x0E) ^ mult(estat[2][i], (byte)0x0B) ^ mult(estat[0][i], (byte)0x0D) ^ mult(estat[3][i],(byte)0x09));
            w[2][i] = (byte) (mult(estat[2][i], (byte)0x0E) ^ mult(estat[3][i], (byte)0x0B) ^ mult(estat[0][i], (byte)0x0D) ^ mult(estat[1][i],(byte)0x09));
            w[3][i] = (byte) (mult(estat[3][i], (byte)0x0E) ^ mult(estat[0][i], (byte)0x0B) ^ mult(estat[2][i], (byte)0x0D) ^ mult(estat[1][i],(byte)0x09));
        }
        return w;
	}
	
	
	public static byte[][] invMixColumn(byte[][] estat) {
	        byte[][] matr = new byte[4][4];
	        for (int i = 0; i < estat.length; ++i) {
	            matr[0][i] = (byte) (mult(estat[0][i], (byte)0x0E) ^ mult(estat[1][i], (byte)0x0B) ^ mult(estat[2][i], (byte)0x0D) ^ mult(estat[3][i], (byte)0x09));
	            matr[1][i] = (byte) (mult(estat[0][i], (byte)0x09) ^ mult(estat[1][i], (byte)0x0E) ^ mult(estat[2][i], (byte)0x0B) ^ mult(estat[3][i], (byte)0x0D));
	            matr[2][i] = (byte) (mult(estat[0][i], (byte)0x0D) ^ mult(estat[1][i], (byte)0x09) ^ mult(estat[2][i], (byte)0x0E) ^ mult(estat[3][i], (byte)0x0B));
	            matr[3][i] = (byte) (mult(estat[0][i], (byte)0x0B) ^ mult(estat[1][i], (byte)0x0D) ^ mult(estat[2][i], (byte)0x09) ^ mult(estat[3][i], (byte)0x0E));
	        }
	        return matr;
	    }
	
	
	/***************************************************
	 ***************** FUNC. PRINCIPALES ***************
	 ***************************************************/
	
	
	public static byte[ ][ ] rijndael(byte[ ][ ] estat, byte[ ][ ][ ] W, int Nk, int Nr){
		// initial round
		estat = addRoundKey(estat,W[0]);
		
		// Nr rounds
		for (int t = 1; t < Nr; ++t){
			
			// byteSub 
			for (int i = 0; i < 4; ++i){
				for (int j = 0; j < 4; ++j){
					estat[i][j] = byteSub(estat[i][j]);
				}
			}
			estat = shiftRow(estat);
			estat = mixColumn(estat);
			estat = addRoundKey(estat,W[t]);
		}
		
		// last round
		for (int i = 0; i < 4; ++i){
			for (int j = 0; j < 4; ++j){
				estat[i][j] = byteSub(estat[i][j]);
			}
		}
		estat = shiftRow(estat);
		estat = addRoundKey(estat,W[Nr]);
		return estat;
	}
	
	
	public static byte[ ][ ] invRijndael(byte[ ][ ] estat, byte[ ][ ][ ] InvW, int Nk, int Nr){
		// initial round
		estat = addRoundKey(estat,InvW[Nr]);
		
		// Nr rounds
		for (int t = Nr - 1; t >= 1; --t){
			// invbyteSub 
			for (int i = 0; i < 4; ++i){
				for (int j = 0; j < 4; ++j){
					estat[i][j] = invByteSub(estat[i][j]);
				}
			}
			estat = invShiftRow(estat);
			estat = invMixColumn(estat);
			estat = addRoundKey(estat,InvW[t]);
		}
		
		// last round
		for (int i = 0; i < 4; ++i){
			for (int j = 0; j < 4; ++j){
				estat[i][j] = invByteSub(estat[i][j]);
			}
		}
		estat = invShiftRow(estat);
		estat = addRoundKey(estat,InvW[0]);
        
		return estat;
	}
	
	
	public static byte[] xifrarAES (byte[] M, byte[] K){
        
        init();
        
		byte[] msg = padMessage(M);					// mensaje con padding
		byte[][][] W = keyExpansion(K);				// subclaves		
		byte[] subMsg = new byte[16];				// bloque de mensaje
        
		// CBC
		int numBlocs = msg.length/16;	
		byte[][][] c = new byte[numBlocs+1][4][4];	// vector de inicializacion
		
		Random rnd = new Random();					// inicializamos aleatoriamente
		for (int i = 0; i <4; ++i){
			rnd.nextBytes(c[0][i]);
		}

		// Para todos los bloques:
		for (int bloc = 1; bloc < numBlocs+1; ++bloc){
			for (int i = 0; i < 16; ++i){
					subMsg[i] = msg[(bloc-1)*16+i];
			}
			byte[][] m = new byte[4][4];
			byte [][] estat = createState(subMsg);
			
			for (int i= 0; i < 4; ++i)
				for (int j = 0; j < 4; ++j)
					m[i][j] = (byte) (estat[i][j] ^ c[bloc-1][i][j]);
			
			c[bloc] = rijndael(m,W,Nk,Nr);
		}
		// transform to array
		byte[] cifrado = new byte[numBlocs*16+16];
		for (int bloc = 0; bloc < numBlocs+1; ++bloc){
			for (int i= 0; i < 4; ++i)
				for (int j = 0; j < 4; ++j)
					cifrado[bloc*16 + i*4 + j] = c[bloc][j][i];
		}
		return cifrado;
	}
	
	
	public static byte[] desxifrarAES (byte[] C, byte[] K){
		byte[][][] W = invKeyExpansion(K);				// subclaves
		
		int numBlocs = C.length/16;	
		byte[][][] m = new byte[numBlocs][4][4];		
		
		
		// Para todos los bloques:
		for (int bloc = 1; bloc < numBlocs; ++bloc){

			byte[][] estat = new byte[4][4];
			for (int i= 0; i < 4; ++i)
				for (int j = 0; j < 4; ++j)
					estat[j][i] = (byte) (C[(bloc)*16 + 4*i + j]);
			
			m[bloc] = invRijndael(estat,W,Nk,Nr);
		}
		
		// transform. to array & CBC
		byte[] descifrado = new byte[(numBlocs-1)*16 ];
		for (int bloc = 1; bloc < numBlocs; ++bloc){
			
			for (int i= 0; i < 4; ++i)
				for (int j = 0; j < 4; ++j)
					descifrado[(bloc-1)*16 + i*4 + j] = (byte) (m[bloc][j][i] ^ C[(bloc-1)*16 + 4*i + j]);
		}
		
		descifrado = quitaPadding(descifrado);
		return descifrado;
	}
	
	
public static void main(String[] args){
		
		
		byte[] m =  {(byte) 0x32,(byte) 0x43,(byte) 0xf6,(byte) 0xa8,
					 (byte) 0x88,(byte) 0x5a,(byte) 0x30,(byte) 0x8d,
					 (byte) 0x31,(byte) 0x31,(byte) 0x98,(byte) 0xa2, 
                     (byte) 0x11,(byte) 0xa2};

		
		byte[] key = {(byte) 0x2b,(byte) 0x7e,(byte) 0x15,(byte) 0x16,
					   (byte) 0x28,(byte) 0xae,(byte) 0xd2,(byte) 0xa6,
					   (byte) 0xab,(byte) 0xf7,(byte) 0x15,(byte) 0x88,
					   (byte) 0x09,(byte) 0xcf,(byte) 0x4f,(byte) 0x3c,
					   (byte) 0x28,(byte) 0xae,(byte) 0xd2,(byte) 0xa6,
					   (byte) 0x28,(byte) 0xae,(byte) 0xd2,(byte) 0xa6};
		

		// CIFRANDO
		for (int l = 1; l < m.length; ++l){
			byte[] mm = new byte[l];
			for (int j = 1; j < l; ++j){
				mm[j] = m[j];
			}
	        byte[] c = xifrarAES(mm,key);
	        
	        
	        // DESCIFRANDO
	        byte[] M = desxifrarAES(c,key);
	        System.out.println();
	        for (int i = 0; i < M.length; ++i){
	        	if (mm[i] != M[i]){
	        		System.out.println("ERROR con longitud de mensaje = "+l);
	        		System.exit(0);
	        	}
	        }
		}
		System.out.println("Todo OK");
       
	}

}

