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
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Random;
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
	 * @throws Exception 
	 */
	public static void main(String[] args) throws Exception {
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
		 byte[] passPhraseByte = null;
		 
		 
		 if (auxInt > 16)
		 {
			 /*
			  * Corto el passphrase introducido a los 16 bytes primeros
			  */
			 grp = aux.substring(0, 16);
			 System.out.println(grp);
			 System.out.println(grp.length());
			 passPhraseByte = grp.getBytes();
			 System.out.println("Array de bytes es: "+ Arrays.toString(passPhraseByte));

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
				 passPhraseByte = new byte [16];
				 Arrays.fill(passPhraseByte, (byte) 0);
				 System.out.println("Array auxiliar es: "+passPhraseByte);
				 byte[] str2 = aux.getBytes();
				 for (int i = 0; i< str2.length;i++)
				 {
					 passPhraseByte[i]=str2[i];
				 }
				 System.out.println("El array final es: " +Arrays.toString(passPhraseByte));
			 }
			 else
			 {
				 /*
				  * La passphrase introducida es de 16 bytes
				  */
				 System.out.println("mido 16");
				 passPhraseByte = aux.getBytes();
				 System.out.println("El array final es: " +Arrays.toString(passPhraseByte));

			 }
		 }
		
		SymmetricCipher sym = new SymmetricCipher();
		RSALibrary rsa = new RSALibrary();

		 
		switch(args[0]){
		case "g":
			
			if (args.length != 1)
			{
				anuncio();
			}
			else
			{
				System.out.println("g option Selected");
				System.out.println("Generating RSA...");
				// Genero las claves públicas y privadas
				rsa.generateKeys();
				// Claves publicas y privadas .key creadas 
				System.out.println("\t Keys generated");
				
				// Cifrar con AES CBC la clave privada
				
				Path path = Paths.get("./private.key");
				
				byte[] privateKB = Files.readAllBytes(path);
				
				
				byte[] cypher_privateKB = sym.encryptCBC(privateKB, passPhraseByte);

				//Sobreescribir la clave privada
				

			}
			break;
		
		case "e":
			
			if (args.length !=3)
			{
				anuncio();
			}
			else
			{
				System.out.println("e option Selected");
				System.out.println("\t Encryption mode");
				
				publicKey = obtainPublicKey();
				
				//Descifrar primero con el passphrase la clave privada
				
				privateKey = obtainPrivateKey();
				//Generamos clave de sesion aleatoria
				String sessionKeyStr = randomString(16);
				byte[] sessionKey = sessionKeyStr.getBytes();
				//Ciframos source file con clave de session
				Path pathSource = Paths.get("./sourceFile.txt");
				byte[] source = Files.readAllBytes(pathSource);
				byte[] cipherSource = sym.encryptCBC(source, sessionKey);
				
				
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
	
	

	private static String randomString( int len ){
		
		String AB = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
		Random rnd = new Random();
		
		StringBuilder sb = new StringBuilder( len );
		for( int i = 0; i < len; i++ ) 
			sb.append( AB.charAt( rnd.nextInt(AB.length()) ) );
		return sb.toString();
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
