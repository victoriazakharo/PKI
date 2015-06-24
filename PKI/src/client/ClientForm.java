package client;

import java.awt.EventQueue;

import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;
import javax.swing.GroupLayout;
import javax.swing.GroupLayout.Alignment;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.LayoutStyle.ComponentPlacement;
import javax.swing.JTextField;

import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.HashSet;
import java.util.Set;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.IOException;

public class ClientForm extends JFrame {

	private JPanel contentPane;
	private JTextField CNField;
	private JTextField OUField;
	private JTextField OField;
	private JTextField LField;
	private JTextField SField;
	private JTextField CField;
	private Client client;
	private String host, port;
	private JTextField hostField;
	private JTextField portField;
	private boolean hasCertificate;
	private JTextField PortField;
	private JTextField HostField;
	private JTextField fileField;
	private Set<ClientFile> clientFiles;
	private JTextField FileField;
	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					ClientForm frame = new ClientForm(null, "0", "0");
					frame.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}

	/**
	 * Create the frame.
	 */
	private boolean askCertificate(String path)
	{
		hasCertificate=false;
		this.client.setDistinguishedName(CNField.getText(), OUField.getText(), OField.getText(), LField.getText(), SField.getText(), CField.getText());
		this.client.askCertificate(path);
		if(this.client.cert!=null)
		{
			JOptionPane.showMessageDialog(rootPane, "Сертификат получен.");
			hasCertificate=true;
			client.initiateThread();
		}
		return hasCertificate;
	}
	
	private boolean connectToClient(String host,String port)
	{
		for(ClientFile file: clientFiles)
		{
			file.dispose();
		}
		clientFiles.clear();
		client.connectToClient(host, port);
		boolean result = client.authorizeClient();
		this.client.writeHostAndPort();
		if(result)
		{
			JOptionPane.showMessageDialog(rootPane, "Авторизация пройдена.");
			return true;
			//dispose();
		}
		else
		{
			JOptionPane.showMessageDialog(rootPane, "Авторизация не пройдена.");
			return false;
		}
	}
	
	public Set<ClientFile> getFiles()
	{
		return this.clientFiles;
	}
	
	private void getFile(String fileName)
	{
		String result=client.getFile(fileName);
		if(result==null || result.equalsIgnoreCase(""))
		{
			result="Отказано в доступе.";
		}
		boolean adding=true;
		ClientFile clientfile=new ClientFile(this, fileName, result);
		for(ClientFile file: clientFiles)
		{
			if(file.contentEquals(fileName, result))
			{
				adding=false;
				break;
			}
		}
		if(adding){
			clientFiles.add(clientfile);
			clientfile.setVisible(true);
		}
		else{
			clientfile.dispose();
			JOptionPane.showMessageDialog(rootPane, "Файл уже открыт.", "", JOptionPane.WARNING_MESSAGE);
		}
	}
	
	private boolean readCertificateAndKeys(String path){
		hasCertificate=false;
		this.client.setDistinguishedName(CNField.getText(), OUField.getText(), OField.getText(), LField.getText(), SField.getText(), CField.getText());
		
		try 
		{
			hasCertificate=client.readCertificateAndPrivateKey(path);
			if(hasCertificate)
			{
				JOptionPane.showMessageDialog(rootPane, "Сертификат считан.");
				hasCertificate=true;
				client.initiateThread();
			}
			else
			{
				JOptionPane.showMessageDialog(rootPane, "Сертификат не считан.");
			}
		} 
		catch (InvalidKeyException | CertificateException | NoSuchAlgorithmException | InvalidKeySpecException | SignatureException | IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return hasCertificate;
	}
	public ClientForm(Client client, String host, String port) {
		addWindowListener(new WindowAdapter() {
			@Override
			public void windowClosing(WindowEvent e) {
				for(ClientFile file: clientFiles)
				{
					file.dispose();
				}
				dispose();
			}
		});
		this.client=client;
		this.host=host;
		this.port=port;
		this.clientFiles=new HashSet<>();
		this.setTitle("Клиент(хост: "+host+"; порт:"+port+")");
		hasCertificate=false;
		setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
		setBounds(100, 100, 504, 342);
		contentPane = new JPanel();
		contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
		setContentPane(contentPane);
		final JLabel certificateResultLabel = new JLabel("\u0421\u0435\u0440\u0442\u0438\u0444\u0438\u043A\u0430\u0442 \u043D\u0435 \u043F\u043E\u043B\u0443\u0447\u0435\u043D");
		PortField = new JTextField();
		PortField.setEnabled(false);
		PortField.setColumns(10);
		
		HostField = new JTextField();
		HostField.setEnabled(false);
		HostField.setColumns(10);
		
		fileField = new JTextField();
		fileField.setEnabled(false);
		fileField.setColumns(10);
		
		final JButton btnNewButton = new JButton("\u041F\u043E\u043B\u0443\u0447\u0438\u0442\u044C \u0444\u0430\u0439\u043B");
		btnNewButton.setEnabled(false);
		btnNewButton.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				String name=fileField.getText();
				getFile(name);
			}
		});
		
		final JLabel lblNewLabel_7 = new JLabel("\u0418\u043C\u044F \u0444\u0430\u0439\u043B\u0430");
		lblNewLabel_7.setEnabled(false);
		
		final JButton attachButton = new JButton("\u041Fo\u0434\u043A\u043B\u044E\u0447\u0438\u0442\u044C\u0441\u044F \u043A \u043A\u043B\u0438\u0435\u043D\u0442\u0443");
		attachButton.setEnabled(false);
		attachButton.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				String host=HostField.getText();
				String port=PortField.getText();
				boolean result=connectToClient(host, port);
				if(result)
				{
					lblNewLabel_7.setEnabled(true);
					btnNewButton.setEnabled(true);
					fileField.setEnabled(true);
				}
				else
				{
					lblNewLabel_7.setEnabled(false);
					btnNewButton.setEnabled(false);
					fileField.setEnabled(false);
				}
			}
		});
		final JLabel lblNewLabel_6 = new JLabel("\u041D\u043E\u043C\u0435\u0440 \u0445\u043E\u0441\u0442\u0430");
		lblNewLabel_6.setEnabled(false);
		
		final JLabel lblNewLabel_8 = new JLabel("\u041D\u043E\u043C\u0435\u0440 \u043F\u043E\u0440\u0442\u0430");
		lblNewLabel_8.setEnabled(false);
		
		JButton certificateButton = new JButton("\u041F\u043E\u043B\u0443\u0447\u0438\u0442\u044C \u0441\u0435\u0440\u0442\u0438\u0444\u0438\u043A\u0430\u0442");
		certificateButton.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				boolean result=askCertificate(FileField.getText());
				if(result)
				{
					certificateResultLabel.setText("Сертификат получен.");
					attachButton.setEnabled(true);
					HostField.setEnabled(true);
					PortField.setEnabled(true);
					lblNewLabel_6.setEnabled(true);
					lblNewLabel_8.setEnabled(true);
				}
				else
				{
					certificateResultLabel.setText("Сертификат не получен.");
					attachButton.setEnabled(false);
					HostField.setEnabled(false);
					PortField.setEnabled(false);
					lblNewLabel_6.setEnabled(false);
					lblNewLabel_7.setEnabled(false);
					lblNewLabel_8.setEnabled(false);
					fileField.setEditable(false);
					btnNewButton.setEnabled(false);
				}
			}
		});
		JLabel lblNewLabel = new JLabel("\u0418\u043C\u044F (CN)");
		
		CNField = new JTextField();
		CNField.setColumns(10);
		
		JLabel lblNewLabel_1 = new JLabel("\u0424\u0438\u043B\u0438\u0430\u043B (OU)");
		
		OUField = new JTextField();
		OUField.setColumns(10);
		
		OField = new JTextField();
		OField.setColumns(10);
		
		LField = new JTextField();
		LField.setColumns(10);
		
		SField = new JTextField();
		SField.setText("");
		SField.setColumns(10);
		
		CField = new JTextField();
		CField.setColumns(10);
		
		JLabel lblNewLabel_2 = new JLabel("\u041E\u0440\u0433\u0430\u043D\u0438\u0437\u0430\u0446\u0438\u044F (O)");
		
		JLabel lblNewLabel_3 = new JLabel("\u0413\u043E\u0440\u043E\u0434 (L)");
		
		JLabel lblNewLabel_4 = new JLabel("\u041E\u0431\u043B\u0430\u0441\u0442\u044C (S)");
		
		JLabel lblNewLabel_5 = new JLabel("\u0421\u0442\u0440\u0430\u043D\u0430 (C)");	
		
		JLabel lblNewLabel_9 = new JLabel("\u041F\u0443\u0442\u044C \u043A \u0444\u0430\u0439\u043B\u0430\u043C");
		
		FileField = new JTextField();
		FileField.setColumns(10);
		
		JButton loadCertificateButton = new JButton("\u0417\u0430\u0433\u0440\u0443\u0437\u0438\u0442\u044C \u0441\u0435\u0440\u0442\u0438\u0444\u0438\u043A\u0430\u0442");
		loadCertificateButton.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				boolean result=readCertificateAndKeys(FileField.getText());
				if(result)
				{
					certificateResultLabel.setText("Сертификат получен.");
					attachButton.setEnabled(true);
					HostField.setEnabled(true);
					PortField.setEnabled(true);
					lblNewLabel_6.setEnabled(true);
					lblNewLabel_8.setEnabled(true);
				}
				else
				{
					certificateResultLabel.setText("Сертификат не получен.");
					attachButton.setEnabled(false);
					HostField.setEnabled(false);
					PortField.setEnabled(false);
					lblNewLabel_6.setEnabled(false);
					lblNewLabel_7.setEnabled(false);
					lblNewLabel_8.setEnabled(false);
					fileField.setEditable(false);
					btnNewButton.setEnabled(false);
				}
			}
		});
		
				
		GroupLayout gl_contentPane = new GroupLayout(contentPane);
		gl_contentPane.setHorizontalGroup(
			gl_contentPane.createParallelGroup(Alignment.LEADING)
				.addGroup(gl_contentPane.createSequentialGroup()
					.addContainerGap()
					.addGroup(gl_contentPane.createParallelGroup(Alignment.LEADING)
						.addComponent(certificateResultLabel)
						.addGroup(gl_contentPane.createSequentialGroup()
							.addGroup(gl_contentPane.createParallelGroup(Alignment.LEADING)
								.addGroup(gl_contentPane.createSequentialGroup()
									.addComponent(lblNewLabel)
									.addGap(68)
									.addComponent(CNField, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
									.addGap(18)
									.addComponent(lblNewLabel_6)
									.addGap(18)
									.addComponent(HostField, GroupLayout.DEFAULT_SIZE, 86, Short.MAX_VALUE)
									.addGap(1))
								.addGroup(gl_contentPane.createSequentialGroup()
									.addGroup(gl_contentPane.createParallelGroup(Alignment.LEADING)
										.addComponent(lblNewLabel_1, GroupLayout.PREFERRED_SIZE, 102, GroupLayout.PREFERRED_SIZE)
										.addComponent(lblNewLabel_2)
										.addComponent(lblNewLabel_3)
										.addComponent(lblNewLabel_4)
										.addComponent(lblNewLabel_5)
										.addComponent(lblNewLabel_9))
									.addPreferredGap(ComponentPlacement.UNRELATED)
									.addGroup(gl_contentPane.createParallelGroup(Alignment.LEADING)
										.addComponent(SField, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
										.addGroup(gl_contentPane.createSequentialGroup()
											.addComponent(OUField, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
											.addGap(18)
											.addComponent(lblNewLabel_8)
											.addGap(18)
											.addComponent(PortField))
										.addGroup(gl_contentPane.createSequentialGroup()
											.addGroup(gl_contentPane.createParallelGroup(Alignment.LEADING)
												.addComponent(OField, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
												.addComponent(LField, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
											.addGap(18)
											.addComponent(attachButton, GroupLayout.DEFAULT_SIZE, 168, Short.MAX_VALUE))
										.addGroup(gl_contentPane.createSequentialGroup()
											.addComponent(CField, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
											.addGap(18)
											.addGroup(gl_contentPane.createParallelGroup(Alignment.LEADING)
												.addComponent(btnNewButton, Alignment.TRAILING, GroupLayout.DEFAULT_SIZE, 168, Short.MAX_VALUE)
												.addGroup(gl_contentPane.createSequentialGroup()
													.addComponent(lblNewLabel_7)
													.addGap(28)
													.addComponent(fileField))))
										.addComponent(FileField, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))))
							.addPreferredGap(ComponentPlacement.RELATED)))
					.addGap(84))
				.addGroup(gl_contentPane.createSequentialGroup()
					.addGroup(gl_contentPane.createParallelGroup(Alignment.TRAILING, false)
						.addComponent(certificateButton, Alignment.LEADING, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
						.addComponent(loadCertificateButton, Alignment.LEADING, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
					.addContainerGap())
		);
		gl_contentPane.setVerticalGroup(
			gl_contentPane.createParallelGroup(Alignment.TRAILING)
				.addGroup(gl_contentPane.createSequentialGroup()
					.addContainerGap()
					.addComponent(certificateResultLabel)
					.addGap(11)
					.addGroup(gl_contentPane.createParallelGroup(Alignment.BASELINE)
						.addComponent(CNField, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
						.addComponent(lblNewLabel_6)
						.addComponent(HostField, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
						.addComponent(lblNewLabel))
					.addPreferredGap(ComponentPlacement.RELATED)
					.addGroup(gl_contentPane.createParallelGroup(Alignment.LEADING)
						.addGroup(gl_contentPane.createSequentialGroup()
							.addGroup(gl_contentPane.createParallelGroup(Alignment.BASELINE)
								.addComponent(lblNewLabel_1)
								.addComponent(OUField, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
							.addPreferredGap(ComponentPlacement.RELATED)
							.addGroup(gl_contentPane.createParallelGroup(Alignment.BASELINE)
								.addComponent(OField, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
								.addComponent(lblNewLabel_2))
							.addPreferredGap(ComponentPlacement.RELATED)
							.addGroup(gl_contentPane.createParallelGroup(Alignment.BASELINE)
								.addComponent(LField, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
								.addComponent(lblNewLabel_3))
							.addPreferredGap(ComponentPlacement.RELATED)
							.addGroup(gl_contentPane.createParallelGroup(Alignment.BASELINE)
								.addComponent(SField, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
								.addComponent(lblNewLabel_4)))
						.addGroup(gl_contentPane.createSequentialGroup()
							.addGroup(gl_contentPane.createParallelGroup(Alignment.BASELINE)
								.addComponent(lblNewLabel_8)
								.addComponent(PortField, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
							.addPreferredGap(ComponentPlacement.UNRELATED)
							.addComponent(attachButton)))
					.addPreferredGap(ComponentPlacement.RELATED)
					.addGroup(gl_contentPane.createParallelGroup(Alignment.BASELINE)
						.addComponent(CField, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
						.addComponent(lblNewLabel_5)
						.addComponent(fileField, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
						.addComponent(lblNewLabel_7))
					.addPreferredGap(ComponentPlacement.RELATED)
					.addGroup(gl_contentPane.createParallelGroup(Alignment.BASELINE)
						.addComponent(FileField, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
						.addComponent(lblNewLabel_9))
					.addGap(18)
					.addGroup(gl_contentPane.createParallelGroup(Alignment.BASELINE)
						.addComponent(certificateButton)
						.addComponent(btnNewButton))
					.addPreferredGap(ComponentPlacement.RELATED)
					.addComponent(loadCertificateButton))
		);
		contentPane.setLayout(gl_contentPane);		this.client=client;
	}
}
