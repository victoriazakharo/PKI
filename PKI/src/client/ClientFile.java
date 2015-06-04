package client;

import java.awt.BorderLayout;
import java.awt.EventQueue;

import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;
import javax.swing.GroupLayout;
import javax.swing.GroupLayout.Alignment;
import javax.swing.JLabel;
import javax.swing.JTextArea;
import javax.swing.LayoutStyle.ComponentPlacement;

import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.HashSet;
import java.util.Set;

public class ClientFile extends JFrame {

	private JPanel contentPane;
	private ClientForm parent;
	private JTextArea textArea;
	private String name, content;
	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					ClientFile frame = new ClientFile(null, "", "");
					frame.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}

	public boolean contentEquals(String name, String text){
		if(this.getTitle().equalsIgnoreCase(name) && textArea.getText().equalsIgnoreCase(text))
		{
			return true;
		}
		return false;
	}
	
	public boolean equalsToClientFile(ClientFile file){
		if(this.getTitle().equalsIgnoreCase(file.getTitle()) && textArea.getText().equalsIgnoreCase(file.getContent()))
		{
			return true;
		}
		return false;
	}
	
	public String getContent(){
		return this.content;
	}
	
	public ClientFile(String name, String text) {
		this.setTitle(name);
		this.name=name;
		this.content=text;
		setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
		setBounds(100, 100, 341, 300);
		contentPane = new JPanel();
		contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
		setContentPane(contentPane);
		
		JLabel lblNewLabel = new JLabel("\u0418\u043C\u044F \u0444\u0430\u0439\u043B\u0430:");
		lblNewLabel.setText(lblNewLabel.getText()+name);
		
		textArea = new JTextArea();
		textArea.setEditable(false);
		textArea.setText(text);
		GroupLayout gl_contentPane = new GroupLayout(contentPane);
		gl_contentPane.setHorizontalGroup(
			gl_contentPane.createParallelGroup(Alignment.LEADING)
				.addGroup(gl_contentPane.createSequentialGroup()
					.addGroup(gl_contentPane.createParallelGroup(Alignment.LEADING)
						.addComponent(lblNewLabel)
						.addGroup(gl_contentPane.createSequentialGroup()
							.addGap(10)
							.addComponent(textArea, GroupLayout.DEFAULT_SIZE, 295, Short.MAX_VALUE)))
					.addContainerGap())
		);
		gl_contentPane.setVerticalGroup(
			gl_contentPane.createParallelGroup(Alignment.LEADING)
				.addGroup(gl_contentPane.createSequentialGroup()
					.addComponent(lblNewLabel)
					.addPreferredGap(ComponentPlacement.UNRELATED)
					.addComponent(textArea, GroupLayout.DEFAULT_SIZE, 216, Short.MAX_VALUE)
					.addContainerGap())
		);
		contentPane.setLayout(gl_contentPane);
	}
	private Set<ClientFile> getParentFiles()
	{
		return this.parent.getFiles();
	}
	/**
	 * @wbp.parser.constructor
	 */
	public ClientFile(ClientForm parent, String name, String text) {
		this.setTitle(name);
		this.parent=parent;
		this.name=name;
		this.content=text;
		setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
		setBounds(100, 100, 341, 300);
		contentPane = new JPanel();
		contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
		setContentPane(contentPane);
		
		JLabel lblNewLabel = new JLabel("\u0418\u043C\u044F \u0444\u0430\u0439\u043B\u0430:");
		lblNewLabel.setText(lblNewLabel.getText()+name);
		
		textArea = new JTextArea();
		textArea.setEditable(false);
		textArea.setText(text);
		
		addWindowListener(new WindowAdapter() {
			@Override
			public void windowClosing(WindowEvent e) {
				Set<ClientFile> files=new HashSet<>();
				files=getParentFiles();
				for(ClientFile file: files){
					if(equalsToClientFile(file)==true){
						files.remove(file);
					}
				}
				dispose();
			}
		});
		GroupLayout gl_contentPane = new GroupLayout(contentPane);
		gl_contentPane.setHorizontalGroup(
			gl_contentPane.createParallelGroup(Alignment.LEADING)
				.addGroup(gl_contentPane.createSequentialGroup()
					.addGroup(gl_contentPane.createParallelGroup(Alignment.LEADING)
						.addComponent(lblNewLabel)
						.addGroup(gl_contentPane.createSequentialGroup()
							.addGap(10)
							.addComponent(textArea, GroupLayout.DEFAULT_SIZE, 295, Short.MAX_VALUE)))
					.addContainerGap())
		);
		gl_contentPane.setVerticalGroup(
			gl_contentPane.createParallelGroup(Alignment.LEADING)
				.addGroup(gl_contentPane.createSequentialGroup()
					.addComponent(lblNewLabel)
					.addPreferredGap(ComponentPlacement.UNRELATED)
					.addComponent(textArea, GroupLayout.DEFAULT_SIZE, 216, Short.MAX_VALUE)
					.addContainerGap())
		);
		contentPane.setLayout(gl_contentPane);
	}
}
