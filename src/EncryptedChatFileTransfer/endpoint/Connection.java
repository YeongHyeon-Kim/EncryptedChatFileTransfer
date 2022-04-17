package EncryptedChatFileTransfer.endpoint;

import javax.crypto.SecretKey;
import java.io.File;
import java.net.Socket;
import java.security.PrivateKey;
import java.security.PublicKey;

public interface Connection  {
	public void start();
	public void stop();
	public Socket getSocket();
	public void sendMessage(Socket socket, SecretKey AESKey, byte[] iv, String data);
	public void sendFile(Socket socket, File file);
	public File getGetFile();
	public void saveFile(File file, String path);
	public void KeyGen();
	public void SendAESKey();
	public SecretKey getAESKey();
	public byte[] getIv();
	public PrivateKey getPrivateKey();
	public PublicKey getPublicKey();
	public void SendKey(Socket socket, PublicKey publicKey);

	public void SaveKey(String path, PublicKey pk, PrivateKey sk);

}
