package client;

import java.awt.BorderLayout;
import java.awt.EventQueue;

import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;
import javax.swing.JButton;
import javax.swing.JTextField;
import javax.swing.GroupLayout;
import javax.swing.GroupLayout.Alignment;
import javax.swing.JTextPane;
import javax.swing.LayoutStyle.ComponentPlacement;
import javax.swing.JLabel;
import javax.swing.JPasswordField;

import crypto.RSA;
import crypto.Shamir.Share;

import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.PublicKey;

public class ClientFrame extends JFrame {

	private JPanel contentPane;
	private JTextField answerField;
	private JLabel label;
	private Integer answer = 0;
	public Boolean answerReady = new Boolean(false);
	ClientThread clientThread;
	String filename, host;
	int port;

	public ClientFrame(ClientThread ct,String filename, String host, int port) {
		setTitle("\u041E\u0442\u043F\u0440\u0430\u0432\u043A\u0430 \u0447\u0430\u0441\u0442\u0438 \u0441\u0435\u043A\u0440\u0435\u0442\u0430");
		this.clientThread = ct;
		this.filename = filename;
		this.host = host;
		this.port = port;
		
		setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
		setBounds(100, 100, 304, 122);
		contentPane = new JPanel();
		contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
		setContentPane(contentPane);
		
		JButton answerButton = new JButton("\u041F\u043E\u0434\u0442\u0432\u0435\u0440\u0434\u0438\u0442\u044C");
		answerButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				String allowString=answerField.getText();
				int allow=0;
				if(allowString.equalsIgnoreCase("да") || allowString.equalsIgnoreCase("yes"))
				{
					allow=1;
				}
				try {
					ClientFrame.this.clientThread.sendingShare(allow, ClientFrame.this.filename);
				} catch (IOException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
				ClientFrame.this.dispose();
			}
		});
		
		answerField = new JTextField();
		answerField.setColumns(10);
		
		label = new JLabel("\u041E\u0442\u043F\u0440\u0430\u0432\u0438\u0442\u044C \u0441\u0435\u043A\u0440\u0435\u0442");
		
		
		GroupLayout gl_contentPane = new GroupLayout(contentPane);
		gl_contentPane.setHorizontalGroup(
			gl_contentPane.createParallelGroup(Alignment.LEADING)
				.addGroup(gl_contentPane.createSequentialGroup()
					.addGroup(gl_contentPane.createParallelGroup(Alignment.LEADING)
						.addGroup(gl_contentPane.createSequentialGroup()
							.addContainerGap()
							.addComponent(label)
							.addPreferredGap(ComponentPlacement.UNRELATED)
							.addComponent(answerField, GroupLayout.DEFAULT_SIZE, 120, Short.MAX_VALUE))
						.addGroup(Alignment.TRAILING, gl_contentPane.createSequentialGroup()
							.addGap(114)
							.addComponent(answerButton, GroupLayout.DEFAULT_SIZE, 120, Short.MAX_VALUE)))
					.addContainerGap())
		);
		gl_contentPane.setVerticalGroup(
			gl_contentPane.createParallelGroup(Alignment.LEADING)
				.addGroup(gl_contentPane.createSequentialGroup()
					.addContainerGap()
					.addGroup(gl_contentPane.createParallelGroup(Alignment.BASELINE)
						.addComponent(answerField, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
						.addComponent(label))
					.addPreferredGap(ComponentPlacement.UNRELATED)
					.addComponent(answerButton)
					.addGap(44))
		);
		contentPane.setLayout(gl_contentPane);
	}

	public synchronized Integer getAnswer() {
		return answer;
	}

	public synchronized void setAnswer(Integer answer) {
		this.answer = answer;
	}

	public synchronized Boolean getAnswerReady() {
		return answerReady;
	}

	public synchronized void setAnswerReady(Boolean answerReady) {
		this.answerReady = answerReady;
	}
}
