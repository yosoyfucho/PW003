/**
 * Data Protection Practical Work 003
 */

/**
 * @author Laura Benito Martín 100284695
 * @author Rafael León Miranda 100275593
 *
 */

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.security.PrivateKey;
import java.security.PublicKey;
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
	 * @throws IOException 
	 * @throws ClassNotFoundException 
	 */
	public static void main(String[] args) throws IOException, ClassNotFoundException {
		// TODO Auto-generated method stub

		PublicKey publicKey = null;
		PrivateKey privateKey = null;
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
			 System.out.println("Array de bytes es: "+ Arrays.toString(auxByte));

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
				 System.out.println("El array final es: " +Arrays.toString(auxByte));
			 }
			 else
			 {
				 /*
				  * La passphrase introducida es de 16 bytes
				  */
				 System.out.println("mido 16");
				 auxByte = aux.getBytes();
				 System.out.println("El array final es: " +Arrays.toString(auxByte));

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
				System.out.println("G option Selected");
				// Genero las claves públicas y privadas
				RSALibrary rsa = new RSALibrary();
				rsa.generateKeys();
				publicKey = obtainPublicKey();
				privateKey = obtainPrivateKey();
				System.out.println("Keys generated");
				
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

	

	private static PrivateKey obtainPrivateKey() throws IOException, ClassNotFoundException {
		
		PrivateKey privateKey = null;
		
		File filePrivateKey = new File("./private.key");

		//Si existe el fichero de clave privada, la obtenemos y desencriptamos
		if(filePrivateKey.exists() && !filePrivateKey.isDirectory()) 
		{ 
			System.out.println("Existe private.key");
			FileInputStream fileInput = new FileInputStream(filePrivateKey);
			ObjectInputStream objectInputStream = new ObjectInputStream(fileInput);
			privateKey = (PrivateKey) objectInputStream.readObject();
			objectInputStream.close();
	
		}
		else
		{
			System.out.println("Archivo de clave privada no creado");
		}
		
		return privateKey;
	}

	private static PublicKey obtainPublicKey() throws IOException, ClassNotFoundException {
		
		PublicKey publicKey = null;
		
		File filePublicKey = new File("./public.key");

		
	
		//Si existe el fichero de clave publica, la obtenemos y encriptamos
		if(filePublicKey.exists() && !filePublicKey.isDirectory()) 
		{ 
			System.out.println("Existe public.key");
			FileInputStream fileInput = new FileInputStream(filePublicKey);
			ObjectInputStream objectInputStream = new ObjectInputStream(fileInput);
			publicKey = (PublicKey) objectInputStream.readObject();
			objectInputStream.close();
		
		}
		else
		{
			System.out.println("Archivo de clave publica no creado");
		}
		return publicKey;
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
