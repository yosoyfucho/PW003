/**
 * Data Protection Practical Work 003
 */

/**
 * @author Laura Benito Martín 100284695
 * @author Rafael León Miranda 100275593
 *
 */

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
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

	public Main() {
		// TODO Auto-generated constructor stub
	}

	/**
	 * @param args
	 * @throws Exception 
	 */
	public static void main(String[] args) throws Exception {
		
		PublicKey publicKey = null;
		PrivateKey privateKey = null;
		
		SymmetricCipher sym = new SymmetricCipher();
		RSALibrary rsa = new RSALibrary();
		
		entrada = new Scanner(System.in);
		System.out.println("Enter the passphrase");
		 
		String passphraseString;
		passphraseString = entrada.next();
		
		//System.out.println(passphraseString);
		
		int passphraseLength, difInt;
		passphraseLength = passphraseString.length();
		System.out.println("Numero de bytes de la passphrase introducida es " + passphraseLength);
		 
		String grp = null;
		byte[] passPhraseByte = new byte [16];
		 
		//Almacenamos la passphrase segun su longitud (cortando o poniendo padding)
		if (passphraseLength > 16)
		{
			//Corto el passphrase introducido a los 16 bytes primeros
			 
			grp = passphraseString.substring(0, 16);
			System.out.println("Passphrase of 16 Bytes: " + grp);
			passPhraseByte = grp.getBytes();
			System.out.println("Passphrase Byte Array: " + Arrays.toString(passPhraseByte));

		}
		else
		{
			if (passphraseLength == 16)
			{				
				//La passphrase introducida es de 16 bytes
				 
				System.out.println("Passphrase of 16: no padding needed");
				passPhraseByte = passphraseString.getBytes();
				System.out.println("Passphrase Byte Array: " + Arrays.toString(passPhraseByte));
			}
			else
			{
				//Si es menor de 16, le ponemos padding PKCS#5 				
				byte[] passPhraseWithoutPaddingByte = passphraseString.getBytes();
				passPhraseByte = addPadding(passPhraseWithoutPaddingByte);
				
				System.out.println("Passphrase Byte Array: " + Arrays.toString(passPhraseByte));
				
			 }
		 }
		 
		//Hacemos una accion u otra dependiendo el parametro introducido por argumento
		switch(args[0]){
		case "g":
			
			if (args.length != 1)
			{
				//Si no tiene el numero de argumentos necesario lanzamos un mensaje
				anuncio();
			}
			else
			{
				System.out.println("g option Selected");
				System.out.println("Generating RSA keys...");
				// Genero las claves publicas y privadas
				rsa.generateKeys();
				// Claves publicas y privadas .key creadas 
				System.out.println("\t Keys generated");
				
				// Cifrar con AES CBC la clave privada
				
				Path path = Paths.get("./private.key");
				
				byte[] privateKeyBytes = Files.readAllBytes(path);
								
				byte[] encryptedPrivateKeyBytes = sym.encryptCBC(privateKeyBytes, passPhraseByte);
				
				//System.out.println("Longitud de los bytes encriptados : " + encryptedPrivateKeyBytes.length);
				
				//Sobreescribir el archivo de clave privada				
				FileOutputStream fileOutputStream = new FileOutputStream("./private.key"); 
				fileOutputStream.write(encryptedPrivateKeyBytes);
				fileOutputStream.close();
				System.out.println("Private Key encrypted with your passphrase");

			}
			break;
		
		case "e":
			
			if (args.length !=3)
			{
				//Si no tiene el numero de argumentos necesario lanzamos un mensaje
				anuncio();
			}
			else
			{
				System.out.println("e option Selected");
				System.out.println("\t Encryption mode");
				
				//Almacenamos el nombre de los ficheros pasados por argumento
				String sourceFileName = args[1];
				String destinationFileName = args[2];
				
				//Obtenemos la clave publica del fichero
				publicKey = obtainPublicKey();
				
				//Obtenemos la clave privada del fichero desencriptandola con la passphrase				
				privateKey = obtainPrivateKey(passPhraseByte);
				
				//Generamos clave de sesion aleatoria
				String sessionKeyStr = randomString(16);
				byte[] sessionKeyBytes = sessionKeyStr.getBytes();
				
				//Leemos el fichero a almacenar
				Path pathSource = Paths.get("./" + sourceFileName);
				byte[] source = Files.readAllBytes(pathSource);
				
				//Ciframos source file con clave de session
				byte[] encryptedSource = sym.encryptCBC(source, sessionKeyBytes);
				
				//Ciframos la clave de sesion con la clave publica del destinatario (en este caso la nuestra propia)
				byte[] encryptedSessionKey = rsa.encrypt(sessionKeyBytes, publicKey);
				
				//Concatenamos la clave de sesion y el source file					
				ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
				outputStream.write(encryptedSessionKey);
				outputStream.write(encryptedSource);
				byte[] encryptedPacket = outputStream.toByteArray();
				
				//Firmamos el paquete concatenado
				byte[] signature = rsa.sign(encryptedPacket, privateKey);

				//Concatenamos el paquete concatenado con su firma				
				ByteArrayOutputStream outputStream2 = new ByteArrayOutputStream();
				outputStream2.write(encryptedPacket);
				outputStream2.write(signature);
				byte[] finalPacket = outputStream2.toByteArray();
								
				//System.out.println("Total length: " + finalPacket.length + " should be " + encryptedSessionKey.length + " + " + encryptedSource.length + " + " + signature.length);		
								
				//Almacenamos el paquete resultante en el fichero destino				
				FileOutputStream fileOutputStream = new FileOutputStream("./" + destinationFileName); 
				fileOutputStream.write(finalPacket);
				fileOutputStream.close();
				System.out.println("Source file encrypted + session key encrypted signed and saved in " + destinationFileName);

				
			}
			break;
			
		case "d":
			
			if (args.length != 3)
			{
				//Si no tiene el numero de argumentos necesario lanzamos un mensaje
				anuncio();			
			}
			else
			{
				System.out.println("D introducida");
				System.out.println("\t Decryption mode");
				
				/*
				 * Formato del paquete
				 * encryptedSessionKey | encryptedSource | signedPacket 
				 * 
				 * */
				//Almacenamos el nombre de los ficheros pasados por argumento
				String fileToDecryptName = args[1];
				String fileToSaveDecryptionName = args[2];
				
				//Leemos el fichero encriptado y lo almacenamos
				Path pathDestination = Paths.get("./" + fileToDecryptName);
				File fileDestination= new File("./" + fileToDecryptName);

				//Comprobamos que existe el fichero a desencriptar
				if(fileDestination.exists() && !fileDestination.isDirectory()){

					byte[] destination = Files.readAllBytes(pathDestination);
					
					//Comprobamos que es mayor de 256 (porque la firma y la clave son 128 cada una)
					if(destination.length > 256){
						
						//Obtenemos la clave publica del fichero public.key
						publicKey = obtainPublicKey();
						
						//Obtenemos la clave privada del fichero private.key desencriptandola con la passphrase						
						privateKey = obtainPrivateKey(passPhraseByte);
						
						int lengthWithoutSignature = destination.length-128;						
						
						byte[] signature= new byte[128];
						byte[] packetToVerify= new byte[lengthWithoutSignature];
						byte[] encryptedSessionKey = new byte[128];
						byte[] txtToDecrypt = new byte[lengthWithoutSignature - 128];
						
						//Separamos la firma del resto del paquete (ultimos 128 Bytes)
						System.arraycopy(destination, lengthWithoutSignature, signature, 0, 128);
						System.arraycopy(destination, 0, packetToVerify, 0, lengthWithoutSignature);
						
						//System.out.println("El array final es: " + Arrays.toString(destination));
						//System.out.println("Array de firma es: " + Arrays.toString(signature));
						

						//Verificamos la firma
						if(rsa.verify(packetToVerify, signature, publicKey) == true){
							
							System.out.println("Signature to verify is correct");
							
							int lengthOfTxt = packetToVerify.length-128;
							
							//Separamos la clave de sesion del texto a desencriptar
							System.arraycopy(packetToVerify, 0, encryptedSessionKey, 0, 128);
							System.arraycopy(packetToVerify, 128, txtToDecrypt, 0, lengthOfTxt);

							//Desencriptamos la clave de sesion
							byte[] decryptedSessionKey = rsa.decrypt(encryptedSessionKey, privateKey);
							
							//Desencripatamos el texto con la clave de sesion que hemos desencriptado
							byte[] decryptedText = sym.decryptCBC(txtToDecrypt, decryptedSessionKey);
							
							//Almacenamos el texto desencriptado en el fichero de destino
							FileOutputStream fileOutputStream = new FileOutputStream("./"+fileToSaveDecryptionName); 
							fileOutputStream.write(decryptedText);
							fileOutputStream.close();
							System.out.println("Decrypted file saved in " + fileToSaveDecryptionName);

						}
						else
						{
							System.out.println("ERROR -- Signature to verify is not correct!");
						}

					}
					else
					{
						System.out.println("ERROR -- File is too small to contain key, signature and text!");
					}
				}
				else
				{
					System.out.println("ERROR -- File " + fileToSaveDecryptionName + " does NOT exists!");
				}

			}
			break;
			
		default:
			
			anuncio();			
			break;
		}
		
	}


	private static PrivateKey obtainPrivateKey(byte[] passPhraseByte) throws Exception {
		
		PrivateKey privateKey = null;
		
		File filePrivateKey = new File("./private.key");
				
		//Si existe el fichero de clave privada, la obtenemos y desencriptamos
		if(filePrivateKey.exists() && !filePrivateKey.isDirectory()) 
		{ 
			System.out.println("Existe private.key");
			
			//Leemos los bytes del fichero
			Path path = Paths.get("./private.key");
			byte[] encryptedPrivateKeyBytes = Files.readAllBytes(path);
			
			//System.out.println("Longitud archivo : " + (int) filePrivateKey.length());
			//System.out.println("Longitud de los bytes encriptados leidos : " + encryptedPrivateKeyBytes.length);
			
			//Desencriptamos con la passphrase la clave privada
			SymmetricCipher sym2 = new SymmetricCipher();				
			byte[] privateKeyBytes = sym2.decryptCBC(encryptedPrivateKeyBytes, passPhraseByte);
					
			//Creamos un fichero temporal del que leer la clave privada desencriptada
			File fileDecryptedPrivateKey = new File("./privateDecrypted.key");
			
			FileOutputStream fileOutputStream = new FileOutputStream(fileDecryptedPrivateKey); 
			fileOutputStream.write(privateKeyBytes);
			fileOutputStream.close();
			
			System.out.println("Private Key decrypted with your passphrase");
			
			//Leemos el fichero desencriptado y lo guardamos como tipo PrivateKey
			FileInputStream fileInput = new FileInputStream(fileDecryptedPrivateKey);
			ObjectInputStream objectInputStream = new ObjectInputStream(fileInput);
			privateKey = (PrivateKey) objectInputStream.readObject();
			objectInputStream.close();
			
			//Eliminamos el fichero de clave privada desencriptada por seguridad
			if(fileDecryptedPrivateKey.delete() == false){
				System.out.println("Be careful! Your decrypted private key could not be deleted!");
			}
			
		}
		else
		{
			System.out.println("ERROR -- File private.key does NOT exists");
		}
		
		return privateKey;
	}

	private static PublicKey obtainPublicKey() throws IOException, ClassNotFoundException {
		
		PublicKey publicKey = null;
		
		File filePublicKey = new File("./public.key");		
	
		//Si existe el fichero de clave publica, la obtenemos y encriptamos
		if(filePublicKey.exists() && !filePublicKey.isDirectory()) 
		{ 
			System.out.println("File public.key found");
			FileInputStream fileInput = new FileInputStream(filePublicKey);
			ObjectInputStream objectInputStream = new ObjectInputStream(fileInput);
			publicKey = (PublicKey) objectInputStream.readObject();
			objectInputStream.close();
		
		}
		else
		{
			System.out.println("ERROR -- File public.key does NOT exists");
		}
		return publicKey;
	}
	
	

	private static String randomString( int len ){
		//Genera un string aleatorio de longitud indicada por parametro
		String AB = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
		Random rnd = new Random();
		
		StringBuilder sb = new StringBuilder( len );
		for( int i = 0; i < len; i++ ) 
			sb.append( AB.charAt( rnd.nextInt(AB.length()) ) );
		return sb.toString();
	}

	private static void anuncio() {
		// TODO Auto-generated method stub
		System.out.println("WARNING-----");
		System.out.println("This application needs:");
		System.out.println("\t for g option: none arguments (java main g)");
		System.out.println("\t for e option: source file and destination file (java main e input output) ");
		System.out.println("\t for d option: source file and destination file (java main d input output) ");
	}
	
	public static byte[] addPadding(byte[] input) throws Exception
	{

		/* El bloque de entrada tendra entre 0 y 15 bytes
		 *
		 * El numero de bytes que faltan seran entre 1 y 16
		 * Se utiliza el formato #PKCS5 que consiste en:
		 * 
		 * Devuelve un array de bytes ya con su padding correspondiente
		 *
		 * */
		
		byte[] blockWithPadding = null;
		int inputLength;

		//Si el array esta vacio la longitud es 0
		if(input == null)
		{
			inputLength= 0;
		}
		else if(input.length >= 16)
		{
			//Si tiene 16 bytes o mas no calculamos padding
			//Para el padding de los bloques enteros le pasamos null
			return null;
		}
		else
		{
			inputLength = input.length;
		}

		int missingBytes = 16 - inputLength;
		//Creamos un array de bytes del tama�o de los bytes que faltan
		byte[] padding = new byte[missingBytes];
		//Rellenamos el array con el valor del numero de bytes que faltan
		Arrays.fill(padding, (byte)missingBytes);
		//System.out.println(Arrays.toString(padding));

		//Concatenamos los dos arrays resultantes
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );

		if(input != null){
			outputStream.write(input);
			outputStream.write(padding);
		}
		else{
			outputStream.write(padding);
		}

		//Convertimos a byte[] de nuevo
		blockWithPadding = outputStream.toByteArray( );
		 
		/*
		 blockWithPadding = concat(input,padding);
		 * */
		return blockWithPadding;
	}

}
