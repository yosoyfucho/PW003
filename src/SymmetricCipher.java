/*
Laura Benito Martin 100284695
Rafael Leon Miranda 100275593
*/

import java.io.ByteArrayOutputStream;
import java.io.FileDescriptor;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import javax.crypto.*;
import java.security.InvalidKeyException;
import java.text.NumberFormat;
import java.util.Arrays;


public class SymmetricCipher {

	byte[] byteKey;
	SymmetricEncryption s;
	SymmetricEncryption d;

	// Initialization Vector (fixed)

	byte[] iv = new byte[] { (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54,
		(byte)55, (byte)56, (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52,
		(byte)53, (byte)54};

    /*************************************************************************************/
	/* Constructor method */
    /*************************************************************************************/
	public void SymmetricCipher() {
	}

    /*************************************************************************************/
	/* Method to encrypt using AES/CBC/PKCS5 */
    /*************************************************************************************/
	public byte[] encryptCBC (byte[] input, byte[] byteKey) throws Exception {

		byte[] ciphertext = null;
		byte[] bytesOfLastBlock = null;
		byte[] bytesOfFullBlocks = null;
		byte[] aux = null;
		
		int bytesSueltos = 0;
		int numBytesFullBlocks = 0;
		int totalBlocks = 0; 
		int textLength = 0;
		int numFullBlocks = 0;
		
		//Longitud total del array de entrada
		textLength = input.length;
		
		//Numero de bloques enteros
		numFullBlocks = (int) textLength/16;
		
		//Numero de bytes que no llega a formar un bloque entero
	    bytesSueltos = textLength % 16;
	  
	    //Numero de bytes totales de todos los bloques enteros
		numBytesFullBlocks = numFullBlocks*16;

		//Array de bytes que incluye todos los bloques enteros
		bytesOfFullBlocks= new byte [numBytesFullBlocks];
    	System.arraycopy(input, 0, bytesOfFullBlocks, 0, numBytesFullBlocks);
    	
		//Coger el ultimo bloque, aplicarle el padding y concatenarlo al texto principal
		
    	
	    //Si hay bytes que no forman un bloque entero necesitamos que el ultimo bloque tenga padding
	    if(bytesSueltos!=0)
	    {
	    	bytesOfLastBlock = new byte[bytesSueltos] ;
	    		    	
	    	//Guarda el array de bytes del ultimo bloque
	    	//Copia desde el byte donde acaban los bloques completos al nuevo array de longitud los bytes que sobraban
	    	System.arraycopy(input, numBytesFullBlocks, bytesOfLastBlock, 0, bytesSueltos);
	    	
	    		    	
	    	//Ponemos el padding necesario al ultimo bloque
	    	bytesOfLastBlock = addPadding(bytesOfLastBlock);
	      
	    }
	    //Si los bloques estan completos se tiene que poner otro nuevo de padding entero
	    else
	    {
	    	
	    	bytesOfLastBlock = addPadding(bytesOfLastBlock);
	    }
	    totalBlocks = numFullBlocks + 1;
	    System.out.println("Numero de bloques que necesita un paquete de " + textLength + " bytes : " + totalBlocks + " bloques");
	    
	    //Concatenamos el ultimo bloque ya de 16B con el resto de bloques enteros	    
	    byte[] textPadd = concat(bytesOfFullBlocks, bytesOfLastBlock);
	    
	    
	    /******************************************************************/
	    
	    byte[] aux2 = new byte[16];
    	byte[] lastCipherBlock = new byte[16];
    	byte[] arrayAfterXOR = new byte[16];
    	byte[] cipherBlock = new byte[16];
    	byte[] totalCipherText = null;
    	
    	//Recorremos todos los bloques
	    for (int i=0; i<totalBlocks; i++)
	    {
	    	//Copiamos el bloque en el que estamos en el array auxiliar
	    	System.arraycopy(textPadd, i*16, aux2, 0, 16);
	    	String auxString = new String(aux2);
	    	System.out.println("Iteraccion numero " + i + " bloque a encriptar " + auxString );
	    	
	    	//Si es la primera iteracion el XOR es con el vector de inicializacion
	    	if(i==0)
	    	{
	    		for(int j=0;j<16;j++)
	    		{
	    			arrayAfterXOR[j] = (byte) (aux2[j] ^ iv[j]);
	    		}
	    	}
	    	//En el resto de iteraciones se hace XOR con el bloque cifrado de la iteracion anterior
	    	else
	    	{
	    		for(int j=0;j<16;j++)
	    		{
	    			arrayAfterXOR[j] = (byte) (aux2[j] ^ cipherBlock[j]);
	    		}	
	    	}
	    	//Usamos una instancia de la clase SymmetricEncription para encriptar el bloque
	    	SymmetricEncryption cipher = new SymmetricEncryption(byteKey);
	    	cipherBlock = cipher.encryptBlock(arrayAfterXOR);
	    	
	    	
	    	
	    	//Concatenamos el bloque encriptado con el resto de bloques encriptados hasta ahora
	    	ciphertext = concat(ciphertext, cipherBlock);
	    	
	    }
	    
		return ciphertext;
	}

	/*************************************************************************************/
	/* Method to decrypt using AES/CBC/PKCS5 */
    /*************************************************************************************/


	public byte[] decryptCBC (byte[] input, byte[] byteKey) throws Exception {

		byte[] finalplaintext = null;
		byte[] plaintext = null;
		byte[] inputBlock = new byte[16];
		byte[] inputPreviousBlock = new byte[16];
		byte[] auxBlock = new byte[16];
		byte[] outputBlock = new byte[16];
		byte[] lastBlock = new byte[16];

		//p[i]= c[i-1] XOR Decrypted(c[i])
		
		//Longitud total del array de entrada
		int textLength = input.length;
				
		//Numero de bloques enteros (en teoria siempre sera multiplo de 16)
		int totalBlocks = (int) textLength/16;
		
		
		// Generate the plaintext
		
		//Recorremos todos los bloques
	    for (int i=0; i<totalBlocks; i++)
	    {
	    	outputBlock = new byte[16];
	    	
	    	//Copiamos el bloque en el que estamos en el array auxiliar
	    	System.arraycopy(input, i*16, inputBlock, 0, 16);
	    	
	    	//Obtenemos C(i-1)
	    	if (i>0){
	    		System.arraycopy(input, (i-1)*16, inputPreviousBlock, 0, 16);	    		
	    	}
	    	
	    	//Obtenemos Decrypted(c[i])
	    	//Usamos una instancia de la clase SymmetricEncription para desencriptar el bloque
	    	SymmetricEncryption cipher = new SymmetricEncryption(byteKey);
	    	auxBlock = cipher.decryptBlock(inputBlock);
	    	
	    	
	    	//Si es la primera iteracion el XOR es con el vector de inicializacion
	    	if(i==0)
	    	{
	    		for(int j=0;j<16;j++)
	    		{
	    			outputBlock[j] = (byte) (auxBlock[j] ^ iv[j]);
	    		}
	    	}
	    	//En el resto de iteraciones se hace XOR con el bloque sin descifrar de la iteracion anterior
	    	else
	    	{
	    		
	    		for(int j=0;j<16;j++)
	    		{
	    			outputBlock[j] = (byte) (auxBlock[j] ^ inputPreviousBlock[j]);
	    		}	
	    	}
	    	String auxStr = new String(outputBlock);
	    	
	    	System.out.println("Iteraccion numero " + i + " bloque a desencriptar: || " + auxStr +" ||" );
	    		    	
	    	plaintext = concat(plaintext, outputBlock);
	    	
	    	
	    	String auxStr3= new String(plaintext);
	    	//System.out.println("Iteraccion numero " + i + " lo que lleva desencriptado tras concatenar : || " + auxStr3 + " || " );	    	
	    }
	   
		// Eliminate the padding
	    
	    System.arraycopy(plaintext, textLength-16, lastBlock, 0, 16);
	    
	    System.out.println("Ultimo bloque: " + Arrays.toString(lastBlock));
	    
	    int numPadding = (int)lastBlock[15];
	    System.out.println("numPadding: "+ numPadding);
	    int plaintextLength = plaintext.length;
	    int finalLength = plaintextLength-numPadding;
	    
	    finalplaintext = new byte[finalLength];
	    System.arraycopy(plaintext, 0, finalplaintext, 0, finalLength );
	    
	    String out = new String(finalplaintext);	    
	    System.out.println("Plaintext final sin padding: " + out);
	    
		return finalplaintext;
	}

	/*
	Function to concatenate two arrays
	*/
	//Tiene que ser static??? Me dio error en mi main...

	public byte[] concat (byte[] a , byte[] b)
	{	
		int aLen;
		int bLen;
		byte[] c;
		
		if(a==null){
			aLen=0;
		}else{
			aLen = a.length;
		}
		
		if(b == null){
			bLen=0;			
		}else{
			bLen = b.length;
		}
		
		if(aLen == 0 && bLen == 0){
			c = null;
		}else if (aLen==0 && bLen != 0){
			c=b;
		}else if (aLen != 0 && bLen == 0){
			c=a;
		}else{
			c = new byte[aLen + bLen];
			System.arraycopy(a,0,c,0,aLen);
			System.arraycopy(b,0,c,aLen,bLen);
		}
		return c;
	}

	
	/*      	>>> Metodo addPadding <<<
	 * El bloque de entrada tendra entre 0 y 15 bytes
	 *
	 * El numero de bytes que faltan seran entre 1 y 16
	 * Se utiliza el formato #PKCS5 que consiste en:
	 * Rellenar los huecos de bytes con el valor numerico
	 * del numero de bytes necesarios
	 * Si faltan 3 bytes, se rellenan 3 bytes con 0x03
	 * Si faltan 2 bytes, se rellenan 2 bytes con 0x02
	 * Si faltan 1 bytes, se rellenan 1 bytes con 0x01
	 *
	 * Devuelve un array de bytes ya con su padding correspondiente
	 *
	 * */
	public byte[] addPadding(byte[] input) throws Exception
	{

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
		//Creamos un array de bytes del tamaño de los bytes que faltan
		byte[] padding = new byte[missingBytes];
		//Rellenamos el array con el valor del numero de bytes que faltan
		Arrays.fill(padding, (byte)missingBytes);
		System.out.println(Arrays.toString(padding));

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
