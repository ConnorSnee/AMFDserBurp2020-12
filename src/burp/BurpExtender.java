package burp;

import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JMenuItem;

public class BurpExtender implements IBurpExtender, IHttpListener, IContextMenuFactory, IMessageEditorTabFactory {
	
	private IBurpExtenderCallbacks callbacks;
	private IExtensionHelpers helpers;

	//IBurpExtender
	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		this.callbacks = callbacks;
		helpers = callbacks.getHelpers();
		
		callbacks.setExtensionName("AMF Deserializer");
		
		callbacks.registerMessageEditorTabFactory(this);
		callbacks.registerContextMenuFactory(this);
		callbacks.registerHttpListener(this);
	}
	
	//IHttpListener
	//Checks requests sent by Scanner, Intruder, and extensions. If they have been deserialized by this extension, serialize them.
	@Override
	public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
		if (messageIsRequest
				&& (toolFlag == callbacks.TOOL_EXTENDER || toolFlag == callbacks.TOOL_SCANNER || toolFlag == callbacks.TOOL_INTRUDER)) {
			try {
				String request = new String(messageInfo.getRequest());
				if (request.contains(Utilities.X_BURP_DESERIALIZED)) {
					byte[] serRequest = Utilities.serializeProxyItem(messageInfo.getRequest());
					if (serRequest != null) {
						messageInfo.setRequest(serRequest);
					}
				}
			} catch (Exception e) {
				callbacks.printError(e.getMessage());
			}
		}
	}
	
	//IContextMenuFactory
	//Adds menu items to send deserialized versions of requests to the Intruder and Scanner tools. Insertion points are auto generated.
	@Override
	public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
		byte context = invocation.getInvocationContext();
		JMenuItem sendToIntruder = new JMenuItem("Send Deserialized AMF to Intruder");
		JMenuItem sendToScanner = new JMenuItem("Scan AMF with with predefined insertion points");
		List<JMenuItem> list = new ArrayList<JMenuItem>();
		if (context == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST || 
				context == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST) {
			sendToIntruder.addActionListener(new ActionListener() {
				@Override
				public void actionPerformed(ActionEvent e) {
					IRequestInfo info = helpers.analyzeRequest(invocation.getSelectedMessages()[0]);
					byte[] request = invocation.getSelectedMessages()[0].getRequest();
					try {
						byte[] deserRequest = Utilities.deserializeProxyItem(request);
						if (deserRequest == null) {
							if (info.getUrl().getProtocol().equalsIgnoreCase("https")) {
								callbacks.sendToIntruder(info.getUrl().getHost(), info.getUrl().getPort(), true, request);
							} else {
								callbacks.sendToIntruder(info.getUrl().getHost(), info.getUrl().getPort(), false, request);
							}
						} else {
							if (info.getUrl().getProtocol().equalsIgnoreCase("https")) {
								callbacks.sendToIntruder(info.getUrl().getHost(), info.getUrl().getPort(), true, deserRequest);
							} else {
								callbacks.sendToIntruder(info.getUrl().getHost(), info.getUrl().getPort(), false, deserRequest);
							}
						}
					} catch (Exception error) {
						callbacks.printError(error.getMessage());
					}
				}
			});
			sendToScanner.addActionListener(new ActionListener() {
				@Override
				public void actionPerformed(ActionEvent e) {
					IRequestInfo info = helpers.analyzeRequest(invocation.getSelectedMessages()[0]);
					byte[] request = invocation.getSelectedMessages()[0].getRequest();
					try {
						byte[] deserRequest = Utilities.deserializeProxyItem(request);
						if (deserRequest == null) {
							if (info.getUrl().getProtocol().equalsIgnoreCase("https")) {
								callbacks.doActiveScan(info.getUrl().getHost(), info.getUrl().getPort(), true, request);
							} else {
								callbacks.doActiveScan(info.getUrl().getHost(), info.getUrl().getPort(), false, request);
							}
						} else {
							if (info.getUrl().getProtocol().equalsIgnoreCase("https")) {
								callbacks.doActiveScan(info.getUrl().getHost(), info.getUrl().getPort(), true, deserRequest);
							} else {
								callbacks.doActiveScan(info.getUrl().getHost(), info.getUrl().getPort(), false, deserRequest);
							}
						}
					} catch (Exception error) {
						callbacks.printError(error.getMessage());
					}
				}
			});
			list.add(sendToIntruder);
			list.add(sendToScanner);
			return list;
		} else {
			return null;
		}
	}
	
	//IMessageEditorTabFactory
	//Adds a tab to view deserialized versions of requests and responses
	@Override
	public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
		return new AMFDserTab(controller, editable);
	}
	
	
	class AMFDserTab implements IMessageEditorTab {
		private boolean editable;
		private ITextEditor txtInput;
		private byte[] currentMessage;
		
		public AMFDserTab(IMessageEditorController controller, boolean editable) {
			this.editable = editable;
			
			txtInput = callbacks.createTextEditor();
			txtInput.setEditable(editable);
		}

		@Override
		public String getTabCaption() {
			return "AMF Deserialized";
		}

		@Override
		public Component getUiComponent() {
			return txtInput.getComponent();
		}

		@Override
		public boolean isEnabled(byte[] content, boolean isRequest) {
			return true;
		}

		@Override
		public void setMessage(byte[] content, boolean isRequest) {
			if (content == null) {
				txtInput.setText(null);
				txtInput.setEditable(false);
			} else {
				try {
					byte[] deserMes = Utilities.deserProxyItem(content);
					if (deserMes == null) {
						txtInput.setText(null);
						txtInput.setEditable(false);
					} else {
						txtInput.setText(deserMes);
					}
				} catch (Exception e) {
					callbacks.printError(e.getMessage());
					txtInput.setText(null);
					txtInput.setEditable(false);
				}	
			}
			currentMessage = content;
		}

		@Override
		public byte[] getMessage() {
			if (txtInput.isTextModified()) {
				try {
					byte[] text = txtInput.getText();
					byte[] serMes = Utilities.serProxyItem(text);
					if (serMes == null) {
						return currentMessage;
					} else {
						return serMes;
					}
				} catch (Exception e) {
					callbacks.printError(e.getMessage());
					return currentMessage;
				}
			} else {
				return currentMessage;
			}
		}

		@Override
		public boolean isModified() {
			return txtInput.isTextModified();
		}

		@Override
		public byte[] getSelectedData() {
			return txtInput.getSelectedText();
		}
		
	}
	

}
