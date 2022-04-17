package EncryptedChatFileTransfer;

import EncryptedChatFileTransfer.client.Client;
import EncryptedChatFileTransfer.endpoint.Connection;
import EncryptedChatFileTransfer.server.Server;
import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.logging.Logger;

public class GUI extends JFrame {
	final public static Logger LOG = Logger.getGlobal();

	static JPanel contentPane;

	static JRadioButton isClient;
	static JRadioButton isServer;

	static Label ipLabel;
	static Label portLabel;
	static TextField ipTextField;
	static TextField portTextField;

	static JButton okButton;

	static public Label statusLabel;
	static public TextArea statusTextArea;


	static JButton keyGenerationButton;
	static JButton keySaveButton;
	static JButton keySendButton;
	static JButton fileLoadButton;
	static JButton fileSendButton;
	static JButton fileSaveButton;
	static JButton SendAESKeyButton;

	static public TextArea chatTextArea;
	static TextField chatTextField;

	static TextArea loadedFileTextArea;
	static public TextArea getFileTextArea;
	static Label loadedFileLabel;
	static Label getFileLabel;

	static public int connectionState = 1;
	//1 = key is not generated
	//2 = key is generated, can send
	//3 = AES key is send to other party or get from other party
	//4 = RSA public key is send to other party or get from other party. can send message
	//5 = 3,4 is complete, RSA signature is ready, send file is ready
	Connection connection;
	static public Date now;
	static public SimpleDateFormat sdf;
	static File loadedFile;

	public GUI(){
		super("IS_assignment_16102268_YeongHyeonKim");
		sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setBounds(0, 0, 900, 1000);
		setBackground(Color.gray);
		contentPane = new JPanel();
		contentPane.setBorder(new EmptyBorder(0, 0, 0, 0));
		setContentPane(contentPane);
		contentPane.setLayout(null);

		isClient = new JRadioButton("Client", false);;
		isClient.setBounds(51,45,186,41);
		contentPane.add(isClient);
		isServer = new JRadioButton("Server", false);
		isServer.setBounds(51,108,186,41);
		contentPane.add(isServer);
		ButtonGroup group = new ButtonGroup();
		group.add(isClient);
		group.add(isServer);


		ipLabel = new Label(" ip :");
		ipLabel.setBounds(299,45,125,41);
		contentPane.add(ipLabel);
		portLabel = new Label(" port :");
		portLabel.setBounds(299,108,125,41);
		contentPane.add(portLabel);
		ipTextField = new TextField("127.0.0.1");
		ipTextField.setBounds(435,45,238,41);
		contentPane.add(ipTextField);
		portTextField= new TextField("1234");;
		portTextField.setBounds(435,108,238,41);
		contentPane.add(portTextField);
		okButton = new JButton("OK");
		ActionListener okButtonActionListener = new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				String ip = ipTextField.getText();
				int port = Integer.parseInt(portTextField.getText());
				if(isClient.isSelected()){
					connection = new Client(ip, port);
					//when Client mode
					SendAESKeyButton.setVisible(true);
					System.out.println("client mode");
				}else if(isServer.isSelected()){

					connection = new Server(ip,port);

					System.out.println("server mode");
				}else{
					//when nothing selected
					JOptionPane.showMessageDialog(null,"please select mode");
					return;
				}
				connection.start();
				return;
			}
		};
		okButton.setBounds(703,45,125,104);
		okButton.addActionListener(okButtonActionListener);
		contentPane.add(okButton);

		statusLabel = new Label("Not connected yet.");
		statusLabel.setBounds(51,206,809,41);
		contentPane.add(statusLabel);

		statusTextArea = new TextArea();
		statusTextArea.setBounds(51,256,809,106);
		contentPane.add(statusTextArea);

		keyGenerationButton = new JButton("Generate Key");
		keyGenerationButton.setBounds(47,374,110,55);
		ActionListener keyGenButtonActionListener = new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				connection.KeyGen();
				now = new Date();
				String nowTime = sdf.format(now);
				statusTextArea.append(nowTime+" :key is generated \n");
				connectionState =2;
			}
		};
		keyGenerationButton.addActionListener(keyGenButtonActionListener);
		contentPane.add(keyGenerationButton);

		keySaveButton = new JButton("Save Key");
		keySaveButton.setBounds(168,374,112,55);
		ActionListener keySaveButtonActionListener = new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				JFileChooser chooser = new JFileChooser();
				int returnVal = chooser.showSaveDialog(null);
				if(returnVal ==0) {
					chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
					File dir = chooser.getSelectedFile();
					String path = dir.getPath();
					connection.SaveKey(path, connection.getPublicKey() ,connection.getPrivateKey());
					now = new Date();
					String nowTime = sdf.format(now);
					statusTextArea.append(nowTime+" :key is saved in "+path+"\n");
				}else{
					return;
				}

				connection.KeyGen();
				now = new Date();
				String nowTime = sdf.format(now);
				statusTextArea.append(nowTime+" :key is generated \n");
				connectionState =2;
			}
		};
		keySaveButton.addActionListener(keySaveButtonActionListener);
		contentPane.add(keySaveButton);

		keySendButton= new JButton("Send Public Key");
		keySendButton.setBounds(327,374,223,55);
		ActionListener keySendButtonActionListener = new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				connection.SendKey(connection.getSocket(), connection.getPublicKey());
			}
		};
		keySendButton.addActionListener(keySendButtonActionListener);
		contentPane.add(keySendButton);



		SendAESKeyButton= new JButton("send AES Key");
		SendAESKeyButton.setBounds(608,374,223,55);
		ActionListener SendAESKeyButtonActionListener = new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				if (connectionState!=2 && connectionState!=4){
					switch (connectionState){
						case 1: JOptionPane.showMessageDialog(null,"please generate key!"); break;
						case 3: JOptionPane.showMessageDialog(null,"key is already send"); break;
						case 5: JOptionPane.showMessageDialog(null,"key is already send"); break;
						default: break;
					}
					System.out.println(connectionState);
					return;
				}
				connection.SendAESKey();

			}
		};
		SendAESKeyButton.addActionListener(SendAESKeyButtonActionListener);
		contentPane.add(SendAESKeyButton);
		SendAESKeyButton.setVisible(false);


		fileLoadButton= new JButton("Load File");
		fileLoadButton.setBounds(47,440,223,55);
		ActionListener fileLoadButtonActionListener = new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				JFileChooser chooser = new JFileChooser();
				int returnVal = chooser.showSaveDialog(null);
				if(returnVal ==0){
					loadedFile = chooser.getSelectedFile();
					loadedFileTextArea.append("========================================= \n");
					now = new Date();
					String nowTime = sdf.format(now);
					loadedFileTextArea.append(nowTime + " : load file complete \n");
					loadedFileTextArea.append("file name : " + loadedFile.getName()+"\n");
					loadedFileTextArea.append("file path : " + loadedFile.getAbsolutePath()+"\n");
					loadedFileTextArea.append("========================================= \n");

				}else{
					return;
				}
			}
		};
		fileLoadButton.addActionListener(fileLoadButtonActionListener);
		contentPane.add(fileLoadButton);


		fileSendButton= new JButton("Send File");
		fileSendButton.setBounds(327,440,223,55);
		ActionListener fileSendButtonActionListener = new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {

				if (connectionState!=5){
					switch (connectionState){
						case 1: JOptionPane.showMessageDialog(null,"please generate key!"); break;
						case 2: JOptionPane.showMessageDialog(null,"please send key"); break;
						case 3: JOptionPane.showMessageDialog(null,"signature not ready"); break;
						case 4: JOptionPane.showMessageDialog(null,"AES key is not arrived"); break;
						default: break;
					}
					return;
				}
				connection.sendFile(connection.getSocket(), loadedFile);
				now = new Date();
				String nowTime = sdf.format(now);
				statusTextArea.append(nowTime+" :File is send \n");
			}
		};
		fileSendButton.addActionListener(fileSendButtonActionListener);
		contentPane.add(fileSendButton);

		fileSaveButton= new JButton("Save File");
		fileSaveButton.setBounds(608,440,223,55);
		ActionListener fileSaveButtonActionListener = new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				if (connection.getGetFile() != null){
					JFileChooser chooser = new JFileChooser();
					int returnVal = chooser.showSaveDialog(null);
					if(returnVal ==0) {
						chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
						File dir = chooser.getSelectedFile();
						String path = dir.getPath();
						connection.saveFile(connection.getGetFile(),path);
						now = new Date();
						String nowTime = sdf.format(now);
						statusTextArea.append(nowTime+" :File is saved \n");
					}else{
						return;
					}
				}else{
					JOptionPane.showMessageDialog(null,"File is not arrived");
				}

			}
		};
		fileSaveButton.addActionListener(fileSaveButtonActionListener);
		contentPane.add(fileSaveButton);

		chatTextArea = new TextArea();
		chatTextArea.setBounds(44,530,816,154);
		contentPane.add(chatTextArea);

		chatTextField = new TextField();
		chatTextField.setBounds(44,695,816,48);
		ActionListener sendChat = new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				if (connectionState!=3 && connectionState!=5){
					switch (connectionState){
						case 1: JOptionPane.showMessageDialog(null,"please generate key!");
							break;
						case 2: JOptionPane.showMessageDialog(null,"please send key!");
							break;
						case 4: JOptionPane.showMessageDialog(null,"AES key has not yet arrived.");
							break;
						default: break;
					}
					return;
				}
				String input = chatTextField.getText();
				connection.sendMessage(connection.getSocket(), connection.getAESKey(), connection.getIv(), input);
				chatTextField.setText("");
			}
		};
		chatTextField.addActionListener(sendChat);
		contentPane.add(chatTextField);

		loadedFileTextArea = new TextArea();
		loadedFileTextArea.setBounds(47,780,400,166);
		contentPane.add(loadedFileTextArea);
		loadedFileLabel = new Label("Loaded File");
		loadedFileLabel.setBounds(194,759,100,20);
		contentPane.add(loadedFileLabel);

		getFileTextArea = new TextArea();
		getFileTextArea.setBounds(460,780,400,166);
		contentPane.add(getFileTextArea);

		getFileLabel = new Label("Get File");
		getFileLabel.setBounds(610,759,55,20);
		contentPane.add(getFileLabel);
		setVisible(true);
	}
	public static void main(String[] args)
	{
		new GUI();
	}
}
