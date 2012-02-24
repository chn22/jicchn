import java.util.ArrayList;
import java.util.List;


public class Token implements UserToken,java.io.Serializable{
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	String serverName, username;
	ArrayList<String> userGroups = new ArrayList<String>();
	
	public Token(String serverName, String username, ArrayList<String> userGroups){
		// TODO complete here
		this.serverName = serverName;
		this.username = username;
		this.userGroups = userGroups;
	}

	@Override
	public String getIssuer() {
		// TODO Auto-generated method stub
		return serverName;
	}

	@Override
	public String getSubject() {
		// TODO Auto-generated method stub
		return username;
	}

	@Override
	public List<String> getGroups() {
		// TODO Auto-generated method stub
		return userGroups;
	}
}
