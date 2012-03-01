import java.util.ArrayList;
import java.util.List;


public class Token implements UserToken,java.io.Serializable{
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	String serverName, username, timestamp;
	ArrayList<String> userGroups = new ArrayList<String>();
	
	public Token(String serverName, String username, ArrayList<String> userGroups, String timestamp){
		// TODO complete here
		this.serverName = serverName;
		this.username = username;
		this.userGroups = userGroups;
		sort(this.userGroups);
		this.timestamp = timestamp;
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
	
	public String getTimestamp(){
		return timestamp;
	}
	
	//get the combined string of all token data
	public String getTokendata(){
		return serverName + username + timestamp + userGroups.toString();
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
