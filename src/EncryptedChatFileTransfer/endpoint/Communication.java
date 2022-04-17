package EncryptedChatFileTransfer.endpoint;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.net.Socket;
import java.nio.file.Files;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Date;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.logging.Level;

import static EncryptedChatFileTransfer.GUI.*;
import static EncryptedChatFileTransfer.GUI.statusTextArea;

public abstract class Communication {
	ExecutorService executorService = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors());

	public void SaveKey(String path, PublicKey pk, PrivateKey sk){
		//save the key as file
		byte[] pkEncode = pk.getEncoded();
		String pkString = new String(Base64.getEncoder().encode(pkEncode));

		byte[] skEncode = sk.getEncoded();
		String skString = new String(Base64.getEncoder().encode(skEncode));
		try{
			OutputStreamWriter osw = new OutputStreamWriter(new FileOutputStream(path+"PublicKey.key"));
			osw.write(pkString,0,pkString.length());
			osw.flush();
			osw.close();
			OutputStreamWriter osw2 = new OutputStreamWriter(new FileOutputStream(path+"PrivateKey.key"));
			osw2.write(skString,0,skString.length());
			osw2.flush();
			osw2.close();

		}catch (Exception e){
			System.out.println("save key :" + e);
		}

	}

	public void SendKey(Socket socket, PublicKey publicKey) {
		Runnable runnable = new Runnable() {
			@Override
			public void run() {
				try {
					//Send Public Key without encryption
					JSONObject finalResult = new JSONObject();
					finalResult.put("header", "public key");
					byte[] enco = publicKey.getEncoded();
					String stringKey = new String(Base64.getEncoder().encode(enco));
					finalResult.put("data", stringKey);
					send(finalResult, socket);
					now = new Date();
					String nowTime = sdf.format(now);
					statusTextArea.append(nowTime+" :public Key is send \n");
					if (connectionState==3){
						//if already get AES key, can make Signature
						connectionState = 5;
						now = new Date();
						nowTime = sdf.format(now);
						statusTextArea.append(nowTime+" :Sign is ready. you can send file \n");
					}else{
						//don't have AES key
						connectionState = 4;
					}
				}catch(Exception e) {
					LOG.log(Level.INFO, "key send error"+e.toString());
				}
			}
		};
		executorService.submit(runnable);
	}

	public void sendMessage(Socket socket, SecretKey AESKey, byte[] iv, String data){
		Runnable runnable = new Runnable() {
			@Override
			public void run() {
				try {
					//send Message with header message
					JSONObject finalResult = new JSONObject();
					finalResult.put("header", "message");
					//encrypt message using AES key
					Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
					c.init(Cipher.ENCRYPT_MODE, AESKey, new IvParameterSpec(iv));
					byte[] encrypted = c.doFinal(data.getBytes("UTF-8"));
					String encrypted_data = new String(Base64.getEncoder().encode(encrypted));
					finalResult.put("data", encrypted_data);
					send(finalResult, socket);
					chatTextArea.append("me    : "+data + "\n");
				}catch(Exception e) {
					System.out.println("send message " + e);
				}
			}
		};
		executorService.submit(runnable);
	}

	public void send(JSONObject encrypted_data, Socket socket) throws IOException {
		OutputStream outputStream = socket.getOutputStream();
		PrintWriter writer = new PrintWriter(outputStream, true);
		writer.println(encrypted_data);
	}
	public abstract void receiveMessage(byte[] data);

	public void saveFile(File file, String path) {
		try{
			//save decrypted file
			File saveFile = new File(path);
			InputStream inputStream = new BufferedInputStream(new FileInputStream(file));
			OutputStream outputStream = new BufferedOutputStream(new FileOutputStream(saveFile));

			byte[] buffer = new byte[1024];
			int read = -1;
			while ((read = inputStream.read(buffer)) > 0) {
				outputStream.write(buffer,0,read);
			}
			outputStream.flush();
			outputStream.close();
			inputStream.close();

			//delete tmp file
			Files.delete(file.toPath());
		}catch (Exception e){
			System.out.println(e);
		}

	};
	public void receive(Socket socket) {
		while(true) {
			try {
				//receive any request JSONObject
				BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
				String getEncryptedMessage = reader.readLine();
				JSONParser parser = new JSONParser();
				JSONObject js =(JSONObject) parser.parse(getEncryptedMessage);
				String header = (String) js.get("header");
				//Classify by looking at headers
				switch (header){
					case "message": {
						String data = (String) js.get("data");
						byte[] encodedData = data.getBytes("UTF-8");
						receiveMessage(encodedData);
						break;
					}
					case "file":{
						receiveFile(js);
						break;
					}
					case "AES Key":{
						receiveAESKey(js);
						break;
					} case "public key":{
						receiveKey(js);
						break;
					}
				}
			}catch (Exception e) {
				System.out.println("receive"+e);
			}
		}
	}
	public abstract void receiveKey(JSONObject js);
	public abstract void receiveAESKey(JSONObject js);
	public abstract void receiveFile(JSONObject js);
}
