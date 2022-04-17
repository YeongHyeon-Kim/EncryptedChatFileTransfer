package EncryptedChatFileTransfer.client;

import EncryptedChatFileTransfer.endpoint.Communication;
import EncryptedChatFileTransfer.endpoint.Connection;
import org.json.simple.JSONObject;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.logging.Level;

import static EncryptedChatFileTransfer.GUI.*;

public class Client extends Communication implements Connection {
	private String ip;
	private int port;
	ExecutorService executorService;
	private Socket socket;
	SecretKey AESKey;
	PublicKey publicRSAKeyFromServer;
	PublicKey RSAPublicKey;
	PrivateKey RSAPrivateKey;
	File getFile;
	byte[] iv;
	@Override
	public Socket getSocket() {
		return socket;
	}
	public PrivateKey getPrivateKey() {
		return RSAPrivateKey;
	}
	public PublicKey getPublicKey() {
		return RSAPublicKey;
	}

	public SecretKey getAESKey() {
		return AESKey;
	}
	public byte[] getIv() {
		return iv;
	}
	public Client(String ip, int port) {
		this.ip = ip;
		this.port = port;
	}

	@Override
	public void start() {
		executorService = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors());
		Runnable runnable = new Runnable() {
			@Override
			public void run() {
				try{
					//connect with Server ip, port
					socket = new Socket();
					socket.connect(new InetSocketAddress(ip, port));
					statusLabel.setText("connected with server");
					receive(socket);
				}catch (Exception e){
					LOG.log(Level.INFO, "client connected with server");
					if(!socket.isClosed()) { stop();}
					return;
				}
			}
		};
		executorService.submit(runnable);
	}

	@Override
	public void stop() {
		try {
			if(socket!=null && !socket.isClosed()) {
				LOG.log(Level.INFO, "stop client");
				socket.close();
			}
		} catch (Exception e) {
			LOG.log(Level.INFO, "stop client error" + e.toString());
		}
	}

	@Override
	public void KeyGen() {
		try {
			//make RSA public key, private key
			KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
			generator.initialize(2048);
			KeyPair keyPair = generator.generateKeyPair();
			RSAPublicKey = keyPair.getPublic();
			RSAPrivateKey = keyPair.getPrivate();

			KeyGenerator gen = KeyGenerator.getInstance("AES");
			gen.init(256);
			AESKey = gen.generateKey();

		} catch (Exception e) {
			e.printStackTrace();
		}
	}


	public void SendAESKey() {
		Runnable runnable = new Runnable() {
			@Override
			public void run() {
				try {
					JSONObject finalResult = new JSONObject();
					finalResult.put("header", "AES Key");

					//Using Server PublicKey, encrypt AES key by RSA method
					Cipher cipher = Cipher.getInstance("RSA");
					cipher.init(Cipher.ENCRYPT_MODE, publicRSAKeyFromServer);
					byte[] encryptedAESByRSA = cipher.doFinal(AESKey.getEncoded());
					SecureRandom random = new SecureRandom();

					//make Initial Vector
					iv = new byte[16];
					random.nextBytes(iv);
					cipher = Cipher.getInstance("RSA");
					cipher.init(Cipher.ENCRYPT_MODE, publicRSAKeyFromServer);
					byte[] encryptedIv = cipher.doFinal(iv);

					String AESString = new String(Base64.getEncoder().encode(encryptedAESByRSA));
					finalResult.put("AES", AESString);
					String IvString =  new String(Base64.getEncoder().encode(encryptedIv));
					finalResult.put("Iv", IvString);

					send(finalResult, socket);

					now = new Date();
					String nowTime = sdf.format(now);
					statusTextArea.append(nowTime+" :send AES key is complete \n");
					statusTextArea.append(nowTime+" :you can chat now \n");
					if(connectionState ==4){
						//if already get public key from the other party, can make Signature
						statusTextArea.append(nowTime+" :Sign is ready. you can send file \n");
						connectionState=5;
					}else{
						//don't have public key from the other party
						connectionState = 3;
					}
				}catch(Exception e) {
					LOG.log(Level.INFO, "key send error"+e.toString());
				}
			}
		};
		executorService.submit(runnable);
	}

	@Override
	public void receiveMessage(byte[] data){
		try {
			//decrypt the Message
			Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
			c.init(Cipher.DECRYPT_MODE, AESKey, new IvParameterSpec(iv));

			byte[] decrypted = Base64.getDecoder().decode(data);
			String result = new String(c.doFinal(decrypted), "UTF-8");
			chatTextArea.append("other : "+result + "\n");
		}catch (Exception e) {
			System.out.println("receive message" +e);
		}
	};
	@Override
	public void receiveKey(JSONObject js) {
		try{
			//receive Public Key which is not encrypted
			String data = (String) js.get("data");
			byte[] encodedData = Base64.getDecoder().decode(data);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			publicRSAKeyFromServer = keyFactory.generatePublic(new X509EncodedKeySpec(encodedData));

			now = new Date();
			String nowTime = sdf.format(now);
			statusTextArea.append(nowTime+" :RSA public key is arrived \n");

		}catch (Exception e){
			LOG.log(Level.INFO, "receive key error"+e.toString());
		}

	}




	@Override
	public File getGetFile() {
		return getFile;
	}


	public void send(JSONObject encrypted_data, Socket socket) throws IOException {
		OutputStream outputStream = socket.getOutputStream();
		PrintWriter writer = new PrintWriter(outputStream, true);
		writer.println(encrypted_data);
	}

	public void receiveFile(JSONObject js){
		try{
			//decrypt file name
			String encryptFileName = (String) js.get("filename");
			byte[] encodedFileName = encryptFileName.getBytes("UTF-8");
			Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
			c.init(Cipher.DECRYPT_MODE, AESKey, new IvParameterSpec(iv));
			byte[] decrypted = Base64.getDecoder().decode(encodedFileName);
			String fileName = new String(c.doFinal(decrypted), "UTF-8");

			String data = (String) js.get("data");
			byte[] encodedData = Base64.getDecoder().decode(data);

			//decode signature
			String signString = (String) js.get("sign");
			byte[] decodeSign = Base64.getDecoder().decode(signString);
			Signature sig = Signature.getInstance("SHA512WithRSA");
			sig.initVerify(publicRSAKeyFromServer);
			sig.update(encodedData);

			//verify the data
			if(!sig.verify(decodeSign)){
				now = new Date();
				String nowTime = sdf.format(now);
				statusTextArea.append(nowTime+" :verify false \n");
				return;
			}
			now = new Date();
			String nowTime = sdf.format(now);
			statusTextArea.append(nowTime+" :verify true \n");
			//decrypt file
			getFile = new File("./tmp"+fileName);
			OutputStream outputStream = new BufferedOutputStream(new FileOutputStream(getFile));
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.DECRYPT_MODE, AESKey, new IvParameterSpec(iv));
			outputStream.write(cipher.doFinal(encodedData));
			outputStream.close();

			now = new Date();
			nowTime = sdf.format(now);
			getFileTextArea.append(nowTime+" : "+ fileName+" is arrived \n");
		}catch (Exception e){
			LOG.log(Level.INFO, "receive FIle" + e);
		}
	}

	@Override
	public void sendFile(Socket socket, File file){
		try {
			//encrypt file
			JSONObject finalResult = new JSONObject();
			finalResult.put("header", "file");

			//encrypt file
			File encryptFile = new File("sendEnc" + file.getPath() );
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, AESKey, new IvParameterSpec(iv));
			byte[] encryptedFile = cipher.doFinal(Files.readAllBytes(file.toPath()));
			String encrypted_data = new String(Base64.getEncoder().encode(encryptedFile));
			finalResult.put("data", encrypted_data);

			//encrypt file name
			Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
			c.init(Cipher.ENCRYPT_MODE, AESKey, new IvParameterSpec(iv));
			byte[] encrypted = c.doFinal(file.getName().getBytes("UTF-8"));
			String encryptedFileName = new String(Base64.getEncoder().encode(encrypted));
			finalResult.put("filename", encryptedFileName);

			//make Signature with RSA private Key
			Signature sig2 = Signature.getInstance("SHA512WithRSA");
			sig2.initSign(RSAPrivateKey);
			sig2.update(encryptedFile);
			byte[] sign = sig2.sign();
			String dataSign = new String(Base64.getEncoder().encode(sign));
			finalResult.put("sign", dataSign);

			//send JSONObject to other party
			send(finalResult, socket);
			now = new Date();
			String nowTime = sdf.format(now);
			statusTextArea.append(nowTime+" :File is send \n");
			Files.delete(encryptFile.toPath());
		}catch (Exception e){
			System.out.println(e);
		}
	}

	@Override
	public void receiveAESKey(JSONObject js) {
	}
}
