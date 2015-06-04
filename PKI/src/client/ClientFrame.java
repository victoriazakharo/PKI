package client;

import java.awt.BorderLayout;
import java.awt.EventQueue;

import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;
import javax.swing.JTextField;
import javax.swing.JButton;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import javax.swing.SwingConstants;

public class ClientFrame extends JFrame {

	private JPanel contentPane;
	private JTextField textField;
	private int answer = 0;

	ClientThread clientThread;
	

	/**
	 * Create the frame.
	 */
	public ClientFrame(ClientThread ct) {
		this.clientThread = ct;
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setBounds(100, 100, 450, 216);
		contentPane = new JPanel();
		contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
		contentPane.setLayout(new BorderLayout(0, 0));
		setContentPane(contentPane);
		
		textField = new JTextField();
		contentPane.add(textField, BorderLayout.NORTH);
		textField.setColumns(10);
		JButton btnAccept = new JButton("Accept");
		btnAccept.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				answer = Integer.valueOf(textField.getText());
				clientThread.answer = answer;
				clientThread.answerReady = true;
				clientThread.setAnswerReady();
				ClientFrame.this.dispose();
			}
		});
		contentPane.add(btnAccept, BorderLayout.CENTER);
	}
	
	public int getAnswer(){
		return answer;
	}

}
