package EncryptedChatFileTransfer.server;

import EncryptedChatFileTransfer.endpoint.Communication;
import EncryptedChatFileTransfer.endpoint.Connection;
import org.json.simple.JSONObject;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.*;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.concurrent.*;

import java.util.logging.Level;

import static EncryptedChatFileTransfer.GUI.*;

public class Server extends Communication implements Connection {
	private String ip;
	private int port;
	byte[] iv;
	SecretKey AESKey;
	PublicKey RSAPublicKey;
	PrivateKey RSAPrivateKey;
	File getFile;
	PublicKey ClientRSAPublicKey;
	ExecutorService executorService;
	ServerSocket serverSocket;
	private Socket socket;


	public PublicKey getPublicKey() {
		return RSAPublicKey;
	}

	@Override
	public File getGetFile() {
		return getFile;
	}

	@Override
	public SecretKey getAESKey() {
		return AESKey;
	}
	@Override
	public byte[] getIv() {
		return iv;
	}

	@Override
	public PrivateKey getPrivateKey() {
		return RSAPrivateKey;
	}

	@Override
	public Socket getSocket() {
		return socket;
	}
	public Server(String ip, int port) {
		this.ip = ip;
		this.port = port;
	}

	@Override
	public void start() {
		executorService = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors());
		try {
			//open server Socket
			serverSocket = new ServerSocket();
			serverSocket.bind(new InetSocketAddress("localhost", 1234));
			System.out.println(ip);
			System.out.println(port);
			statusLabel.setText("server is running in IP : " + ip +"/"+ port);
		} catch (Exception e) {
			LOG.log(Level.INFO, "start error" +e);
			if (!serverSocket.isClosed()) {
				stop();
				return;
			}
		}
		Runnable runnable = new Runnable() {
			@Override
			public void run() {
					try {
						//When a connection request is received from the other party
						socket = serverSocket.accept();
						LOG.log(Level.INFO, "sever connected with client");
						statusLabel.setText(statusLabel.getText()+"\n connected with Client");

						//wait input from the other side
						receive(socket);
					} catch (Exception e) {
						LOG.log(Level.INFO, "run error" +e.toString());
						if (!serverSocket.isClosed()) {
							stop();
						}
					}
				}
			};
		executorService.submit(runnable);
	}

	@Override
	//Stop Server
	public void stop() {
		try {
			LOG.log(Level.INFO, "sever stop");
			if (serverSocket != null && !serverSocket.isClosed()) {
				serverSocket.close();
			}
			if (executorService != null && !executorService.isShutdown()) {
				executorService.shutdown();
			}
			statusLabel.setText("sever is closed");
		} catch (Exception e) {
			LOG.log(Level.INFO, "stop error" + e.toString());
		}
	}

	@Override
	public void KeyGen() {
		try {
			//make RSA Public Key and Private Key
			KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
			generator.initialize(2048);
			KeyPair keyPair = generator.generateKeyPair();
			RSAPublicKey = keyPair.getPublic();
			RSAPrivateKey = keyPair.getPrivate();
		}catch (Exception e){
			LOG.log(Level.INFO, "key generation error"+e.toString());
		}
	}

	@Override
	public void receiveAESKey(JSONObject js) {
		try{
			String data = (String) js.get("AES");
			byte[] encodedData = Base64.getDecoder().decode(data);
			//byte array to AES Key
			AESKey = new SecretKeySpec(DecryptRSA(encodedData, RSAPrivateKey), "AES");
			String ivString = (String) js.get("Iv");
			byte[] encodedIvString = Base64.getDecoder().decode(ivString);
			//get Initial Vector
			iv = DecryptRSA(encodedIvString, RSAPrivateKey);
			now = new Date();
			String nowTime = sdf.format(now);
			statusTextArea.append(nowTime+" :AES key is arrived \n");
			statusTextArea.append(nowTime+" :you can chat now \n");
			if (connectionState==4){
				//if already get the other side Public Key, can make Signature
				connectionState = 5;
				now = new Date();
				nowTime = sdf.format(now);
				statusTextArea.append(nowTime+" :Sign is ready. you can send file \n");
			}else{
				//if don't have the other side Public Key
				connectionState = 3;
			}
		}catch (Exception e){
			LOG.log(Level.INFO, "receive key server :" + e);
		}

	}

	@Override
	public void receiveMessage(byte[] data){
		try {
			//decrypt Message
			Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
			c.init(Cipher.DECRYPT_MODE, AESKey, new IvParameterSpec(iv));
			byte[] decrypted = Base64.getDecoder().decode(data);
			String result = new String(c.doFinal(decrypted), "UTF-8");
			chatTextArea.append("other : "+result + "\n");
		}catch (Exception e) {
			System.out.println("receive message" +e);
		}
	}

	@Override
	public void receiveKey(JSONObject js) {
		try{
			//Receive Public Key
			String data = (String) js.get("data");
			byte[] encodedData = Base64.getDecoder().decode(data);
			//byte array to Public Key
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			ClientRSAPublicKey = keyFactory.generatePublic(new X509EncodedKeySpec(encodedData));

			now = new Date();
			String nowTime = sdf.format(now);
			statusTextArea.append(nowTime+" : RSA public key is arrived \n");

			if (connectionState==3){
				//if already get AES Key --> can make Signature
				connectionState = 5;
				now = new Date();
				nowTime = sdf.format(now);
				statusTextArea.append(nowTime+" :Sign is ready. you can send file \n");
			}else{
				//if don't have AES key
				connectionState = 4;
			}
		}catch (Exception e){
			LOG.log(Level.INFO, "receive key error"+e.toString());
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

			//make Signature
			Signature sig = Signature.getInstance("SHA512WithRSA");
			sig.initSign(RSAPrivateKey);
			sig.update(encryptedFile);
			byte[] sign = sig.sign();
			String dataSign = new String(Base64.getEncoder().encode(sign));
			finalResult.put("sign", dataSign);

			//send file
			send(finalResult, socket);
			now = new Date();
			String nowTime = sdf.format(now);
			statusTextArea.append(nowTime+" :File is send \n");
			encryptFile.delete();

		}catch (Exception e){
			System.out.println("send file server " + e);
		}
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
			sig.initVerify(ClientRSAPublicKey);
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
			cipher.init(Cipher.DECRYPT_MODE,  AESKey, new IvParameterSpec(iv));

			outputStream.write(cipher.doFinal(encodedData));
			outputStream.close();

			now = new Date();
			nowTime = sdf.format(now);
			getFileTextArea.append(nowTime+" : "+ fileName+" is arrived \n");

		}catch (Exception e){
			LOG.log(Level.INFO, "receive FIle" + e);
		}

	}


	public byte[] DecryptRSA(byte[] encrypted, PrivateKey privateKey) {
		byte[] decryptedRSA = null;
		try {

			Cipher cipher = Cipher.getInstance("RSA");

			cipher.init(Cipher.DECRYPT_MODE, privateKey);
			decryptedRSA = cipher.doFinal(encrypted);

		} catch (Exception e) {
			e.printStackTrace();
		}

		return decryptedRSA;
	}
	@Override
	public void SendAESKey() {
	}
}
