import java.util.ArrayList;
import java.util.Date;
import java.util.List;


public class Token implements UserToken,java.io.Serializable{
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	String serverName, username;
	Date timestamp;
	ArrayList<String> userGroups = new ArrayList<String>();
	byte[] signature;
	
	public Token(String serverName, String username, ArrayList<String> userGroups, Date timestamp){
		// TODO complete here
		this.serverName = serverName;
		this.username = username;
		this.userGroups = userGroups;
		sort(this.userGroups);
		this.timestamp = timestamp;
		signature = null;
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
	
	public Date getTimestamp(){
		return timestamp;
	}
	
	//get the combined string of all token data
	public String getTokendata(){
		return serverName + username + timestamp.toString() + userGroups.toString();
	}
	
	public void setSignature(byte[] bytes){
		signature = bytes;
	}
	
	public byte[] getSignature(){
		return signature;
	}
	
	//sort the arraylist
	public void sort(ArrayList<String> list){
		String small;
		int least;
		for(int i = 0; i < list.size() - 1; i++){
			small = list.get(i);
			least = i;
			for(int j = i + 1; j < list.size(); j++){
				if(list.get(j).compareTo(small) < 1){
					small = list.get(j);
					least = j;
				}
			}
			if(least != i){
				String temp = list.get(i);
				list.set(i, small);
				list.set(least, temp);
			}
		}
	}
}
