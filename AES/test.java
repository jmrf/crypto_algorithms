/***************************************************
***************** TEST FUNCTIONS ******************
***************************************************/
	
	private static void checkTables(){
		for (int i = 0; i < GF.length; ++i){
			System.out.printf("%02x ",GF[i]);
			if (i % 16 == 0)
				System.out.println();
		}
		System.out.println();
		System.out.println();
		for (int i = 0; i < log.length; ++i){
			System.out.printf("%02x ",log[i]);
			if (i % 16 == 0)
				System.out.println();
		}
		System.out.println("\n");
	}
	
	private static void checkState(byte[] m){
        byte s[][] = createState(m);
        for (int f = 0; f < s.length; ++f){
            for (int c = 0; c < s[0].length; ++c){
                    System.out.printf("%02x ", s[f][c]);
            }
            System.out.println();
        } 
	}
	
	
	private static void checkKeyExpansion(byte [][][] kexp){
		for (int i = 0; i < kexp.length; ++i){
			for (int j = 0; j < 4; ++j){
				for (int k = 0; k < 4; ++k){
					System.out.printf("%02x ", kexp[i][j][k]);
				}
				System.out.println();
			}
			System.out.println();
		}
	}
	
	
	




/***************************************************
********************** MAIN ***********************
***************************************************/
	
    
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
//	        for (int i = 0; i < c.length; ++i){
//	        	System.out.printf("%02x ", c[i]);
//	        	if (i % 16 == 0) System.out.println();
//	        }
//	        System.out.println("\n-------------------------------------------\n");
	        
	        
	        // DESCIFRANDO
	        byte[] M = desxifrarAES(c,key);
	        System.out.println();
	        for (int i = 0; i < M.length; ++i){
	        	if (mm[i] != M[i]){
	        		System.out.println("ERROR con longitud de mensaje = "+l);
	        		System.exit(0);
	        	}
	//        	System.out.printf("%02x ", M[i]);
//	        	if (i % 16 == 0 && i != 0) System.out.println();
	        }
		}
		System.out.println("Todo OK");
       
	}