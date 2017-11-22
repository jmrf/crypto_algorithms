import java.math.BigInteger;

public class sha512 {
	
	// Constants
	private static long[] h = {
		0x6a09e667f3bcc908L,
		0xbb67ae8584caa73bL,
		0x3c6ef372fe94f82bL,
		0xa54ff53a5f1d36f1L,
		0x510e527fade682d1L,
		0x9b05688c2b3e6c1fL,
		0x1f83d9abfb41bd6bL,
		0x5be0cd19137e2179L
	};
	
	private static long[] K = {
			0x428a2f98d728ae22L, 0x7137449123ef65cdL, 0xb5c0fbcfec4d3b2fL, 0xe9b5dba58189dbbcL,
			0x3956c25bf348b538L, 0x59f111f1b605d019L, 0x923f82a4af194f9bL, 0xab1c5ed5da6d8118L,
			0xd807aa98a3030242L, 0x12835b0145706fbeL, 0x243185be4ee4b28cL, 0x550c7dc3d5ffb4e2L,
			0x72be5d74f27b896fL, 0x80deb1fe3b1696b1L, 0x9bdc06a725c71235L, 0xc19bf174cf692694L,
			0xe49b69c19ef14ad2L, 0xefbe4786384f25e3L, 0x0fc19dc68b8cd5b5L, 0x240ca1cc77ac9c65L,
			0x2de92c6f592b0275L, 0x4a7484aa6ea6e483L, 0x5cb0a9dcbd41fbd4L, 0x76f988da831153b5L,
			0x983e5152ee66dfabL, 0xa831c66d2db43210L, 0xb00327c898fb213fL, 0xbf597fc7beef0ee4L,
			0xc6e00bf33da88fc2L, 0xd5a79147930aa725L, 0x06ca6351e003826fL, 0x142929670a0e6e70L,
			0x27b70a8546d22ffcL, 0x2e1b21385c26c926L, 0x4d2c6dfc5ac42aedL, 0x53380d139d95b3dfL,
			0x650a73548baf63deL, 0x766a0abb3c77b2a8L, 0x81c2c92e47edaee6L, 0x92722c851482353bL,
			0xa2bfe8a14cf10364L, 0xa81a664bbc423001L, 0xc24b8b70d0f89791L, 0xc76c51a30654be30L,
			0xd192e819d6ef5218L, 0xd69906245565a910L, 0xf40e35855771202aL, 0x106aa07032bbd1b8L,
			0x19a4c116b8d2d0c8L, 0x1e376c085141ab53L, 0x2748774cdf8eeb99L, 0x34b0bcb5e19b48a8L,
			0x391c0cb3c5c95a63L, 0x4ed8aa4ae3418acbL, 0x5b9cca4f7763e373L, 0x682e6ff3d6b2b8a3L,
			0x748f82ee5defb2fcL, 0x78a5636f43172f60L, 0x84c87814a1f0ab72L, 0x8cc702081a6439ecL,
			0x90befffa23631e28L, 0xa4506cebde82bde9L, 0xbef9a3f7b2c67915L, 0xc67178f2e372532bL,
			0xca273eceea26619cL, 0xd186b8c721c0c207L, 0xeada7dd6cde0eb1eL, 0xf57d4f7fee6ed178L,
			0x06f067aa72176fbaL, 0x0a637dc5a2c898a6L, 0x113f9804bef90daeL, 0x1b710b35131c471bL,
			0x28db77f523047d84L, 0x32caab7b40c72493L, 0x3c9ebe0a15c9bebcL, 0x431d67c49c100d4cL,
			0x4cc5d4becb3e42b6L, 0x597f299cfc657e2aL, 0x5fcb6fab3ad6faecL, 0x6c44198c4a475817L
	};
	
	private static long ch(long x, long y, long z){
		return (x & y) ^ (~x & z);
	}
	
	private static long maj(long x, long y, long z){
		return (x & y) ^ (x & z) ^ (y & z);
	}
	
	private static long rotR(long A, int n){
		int w = 64 - n;
		return (A >>> n) | (A << w);
	}
	
	private static long shR(long A, int n){
		return A >>> n;
	}
	
	private static long Sigma_0(long x){
		return rotR(x, 28) ^ rotR(x,34) ^ rotR(x,39);
	}
	
	private static long Sigma_1(long x){
		return rotR(x, 14) ^ rotR(x,18) ^ rotR(x,41);
	}
	
	private static long sigma_0(long x){
		return rotR(x, 1) ^ rotR(x,8) ^ shR(x,7);
	}
	
	private static long sigma_1(long x){
		return rotR(x, 19) ^ rotR(x,61) ^ shR(x,6);
	}
	
	private static byte[] padding(byte[] M){
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
	
    private static byte[] concatena(long[] H){
        byte[] res = new byte[64];
        int desp = 56;
        for (int i = 0;i < H.length; ++i){
        	for (int j = 0; j < 8; ++j){
                res[i*8+j] = (byte) (H[i] >>> desp & 0xFF);
        		desp -= 8;
        		//System.out.printf("%02x",res[i+j]);
        	}
        	desp = 56;
        }
        return res;
    }
	
    // no haria falta hacer modulo trunca cuando se pasa
	private static long suma(long A, long B){
		BigInteger a = new BigInteger(Long.toString(A));
		BigInteger b = new BigInteger(Long.toString(B));
		BigInteger mod = new BigInteger("2").pow(64);
		return a.add(b).mod(mod).longValue();
	}
	
	
	
	/**
	 * Hash function
	 * @param M: message to hash
	 * @return a 512 bits length message
	 */
	public static byte[] hash(byte[] M){
		long[] H = {
                    0x6a09e667f3bcc908L,
                    0xbb67ae8584caa73bL,
                    0x3c6ef372fe94f82bL,
                    0xa54ff53a5f1d36f1L,
                    0x510e527fade682d1L,
                    0x9b05688c2b3e6c1fL,
                    0x1f83d9abfb41bd6bL,
                    0x5be0cd19137e2179L
                };
                
                /*
                for (int i = 0; i < H.length; ++i){
                    System.out.println(Long.toHexString(H[i]));
                }
                System.out.println();*/
                
		byte[] hash = new byte[64];
		// prepare the message
		byte[] m = padding(M);
		
		int n = m.length*8/1024;
		// For each 1024 bits bloc:
		for (int t = 0; t < n; ++t){
			int iniBlocIndex = t*(1024/8);
			long[] W = new long[80];
			// For all 16 first chunks: decompose in 64 bits (8 Bytes) length
			for (int ch = 0; ch < 16; ++ch){
				W[ch] = ((long)m[iniBlocIndex+ch*8] << 56) & 0xFF00000000000000L
						| ((long)m[iniBlocIndex+ch*8+1] << 48) & 0x00FF000000000000L
						| ((long)m[iniBlocIndex+ch*8+2] << 40) & 0x0000FF0000000000L
						| ((long)m[iniBlocIndex+ch*8+3] << 32) & 0x000000FF00000000L
						| ((long)m[iniBlocIndex+ch*8+4] << 24) & 0x00000000FF000000L
						| ((long)m[iniBlocIndex+ch*8+5] << 16) & 0x0000000000FF0000L
						| ((long)m[iniBlocIndex+ch*8+6] << 8) & 0x000000000000FF00L
						| ((long)m[iniBlocIndex+ch*8+7]) & 0x00000000000000FFL;
                                //System.out.println(Long.toHexString(W[ch]));
			}
			// For all 16 to 80 blocs:
			for (int ch = 16; ch < 80; ++ch){
				W[ch] = sigma_1(W[ch-2]) + W[ch-7] + sigma_0(W[ch-15]) + W[ch-16];
				//W[ch] = suma(suma(sigma_1(W[ch-2]),W[ch-7]),suma(sigma_0(W[ch-15]),W[ch-16]));
			}
			// initializations:
			long a = H[0];
			long b = H[1];
			long c = H[2];
			long d = H[3];
			long e = H[4];
			long f = H[5];
			long g = H[6];
			long h = H[7];
			// For 80 rounds:
			for (int r = 0; r < 80; ++r){
				long T1 = h + Sigma_1(e) + ch(e,f,g) + K[r] + W[r];
				long T2 = Sigma_0(a) + maj(a,b,c);
				h = g;
				g = f;
				f = e;
				e = d + T1;
				d = c;
				c = b;
				b = a;
				a = T1 + T2;
			}
			// updating H
			H[0] += a;
			H[1] += b;
			H[2] += c;
			H[3] += d;
			H[4] += e;
			H[5] += f;
			H[6] += g;
			H[7] += h;
		}
		// printamos el resultado
//		for (int i = 0; i < 8; ++i){
//				System.out.println(Long.toHexString(H[i]).toLowerCase());
//		}
		hash = concatena(H);
		return hash;
	}
	
 	/*public static void main(String[] args) {
         //String s = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
         //byte[] bs = s.getBytes();
         byte[] bs = new byte[1000000];
         for (int i = 0; i < 1000000; ++i)
             bs[i] = 0x61;
         
         //System.out.println("original length: "+bs.length*8);
         byte[] sha = hash(bs);
         int bytes_printed = 0;
         for (int i = 0; i < sha.length; ++i){
        	System.out.printf("%02x",sha[i]);					// 02 -> dos digitos por num | x -> base hexadecimal
        	bytes_printed++;
                if (bytes_printed == 8){ 
                    System.out.print(" ");
                    bytes_printed = 0;
                }
         }
         System.out.println();
         
         sha = hash(bs);
         for (int i = 0; i < sha.length; ++i){
        	System.out.printf("%02x",sha[i]);					// 02 -> dos digitos por num | x -> base hexadecimal
        	bytes_printed++;
                if (bytes_printed == 8){ 
                    System.out.print(" ");
                    bytes_printed = 0;
                }
         }
         System.out.println();
         //System.out.println(new BigInteger(sha).toString(16));
      }*/
}
