/**
 * Data Protection Practical Work 003
 */

/**
 * @author Laura Benito Martín 100284695
 * @author Rafael León Miranda 100275593
 *
 */

import java.util.Arrays;
import java.util.Scanner;
public class Main {

	private static Scanner entrada;

	/**
	 * 
	 */
	public Main() {
		// TODO Auto-generated constructor stub
	}

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		// TODO Auto-generated method stub

		 System.out.println(args[0]); // Se puede borrar
		 System.out.println(args.length); // Se puede borrar
		
		 entrada = new Scanner(System.in);
		 System.out.println("Enter the passphrase");
		 
		 String aux;
		 aux = entrada.next();
		 System.out.println(aux);
		 int auxInt, difInt;
		 auxInt = aux.length();
		 System.out.println("Numero de bytes en aux es "+auxInt);
		 String grp = null;
		 byte[] auxByte = null;
		 if (auxInt > 16)
		 {
			 /*
			  * Corto el passphrase introducido a los 16 bytes primeros
			  */
			 grp = aux.substring(0, 16);
			 System.out.println(grp);
			 System.out.println(grp.length());
			 auxByte = grp.getBytes();
			 System.out.println("Array de bytes es: "+auxByte);

		 }
		 else
		 {
			 if (auxInt!=16)
			 {
				 /*
				  * La passphrase introducida es menor de 16 bytes
				  */
				 difInt = 16 - auxInt;
				 System.out.println( "Hac falta un relleno de :"+difInt);
				 auxByte = new byte [16];
				 Arrays.fill(auxByte, (byte) 0);
				 System.out.println("Array auxiliar es: "+auxByte);
				 byte[] str2 = aux.getBytes();
				 for (int i = 0; i< str2.length;i++)
				 {
					 auxByte[i]=str2[i];
				 }
				 System.out.println("El array final es: " +auxByte);
			 }
			 else
			 {
				 /*
				  * La passphrase introducida es de 16 bytes
				  */
				 System.out.println("mido 16");
			 }
		 }
		 
		 
		switch(args[0]){
		case "g":
			
			if (args.length != 1)
			{
				anuncio();
			}
			else
			{
				System.out.println("G introducida");
				// Genero las claves públicas y privadas
			}
			break;
		
		case "e":
			
			if (args.length !=3)
			{
				anuncio();
			}
			else
			{
				System.out.println("E introducida");
			}
			break;
			
		case "d":
			
			if (args.length != 3)
			{
				anuncio();			
			}
			else
			{
				System.out.println("D introducida");
			}
			break;
			
		default:
			
			anuncio();			
			break;
		}
		
		
		
	}

	
	private static void anuncio() {
		// TODO Auto-generated method stub
		System.out.println("Warning Error-----");
		System.out.println("This application needs:");
		System.out.println("\t for g option: none arguments (java main g)");
		System.out.println("\t for e option: source file and destination file (java main e input output) ");
		System.out.println("\t for d option: source file and destination file (java main d input output) ");
	}

}
