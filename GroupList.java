/* This list represents the users on the server */
import java.util.*;


	public class GroupList implements java.io.Serializable {
	
		/**
		 * 
		 */
		private static final long serialVersionUID = 7611343803563417992L;
		private Hashtable<String, Group> list = new Hashtable<String, Group>();
		
		public synchronized void addGroup(String username)
		{
			Group newGroup = new Group();
			list.put(username, newGroup);
		}
		
		public synchronized void deleteGroup(String group)
		{
			list.remove(group);
		}
		
		
		public synchronized boolean checkGroup(String group)
		{
			if(list.containsKey(group))
			{
				return true;
			}
			else
			{
				return false;
			}
		}
		
		public synchronized boolean checkMembership(String group, String username)
		{
			return list.get(group).checkMembership(username);
		}
		
		public synchronized ArrayList<String> getMembers(String group)
		{
			return list.get(group).getMembers();
		}
		
		public synchronized void addMember(String group, String username)
		{
			list.get(group).addMember(username);
		}
		
		public synchronized void removeMember(String group, String username)
		{
			list.get(group).removeMember(username);
		}
		
		public synchronized void addVersionKey(String group, byte[] key){
			list.get(group).addVersionKey(key);
		}
		
		public synchronized int getCurrent(String group){
			return list.get(group).getCurrent();
		}
		
		public synchronized ArrayList<byte[]> getVersionKeys(String group){
			return list.get(group).getVersionKeys();
		}
		
	class Group implements java.io.Serializable {

		/**
		 * 
		 */
		private static final long serialVersionUID = -6699986336399821598L;
		private ArrayList<String> members;
		private ArrayList<byte[]> versionKey;
		
		public Group()
		{
			members = new ArrayList<String>();
			versionKey = new ArrayList<byte[]>();
		}
		
		public ArrayList<String> getMembers()
		{
			return members;
		}
		
		public void addMember(String username)
		{
			members.add(username);
		}
		
		public void removeMember(String username)
		{
			members.remove(members.indexOf(username));
		}
		
		public boolean checkMembership(String username)
		{
			if(members.contains(username))
			{
				return true;
			}
			else
			{
				return false;
			}
		}
		
		public byte[] getVersionKey(int n){
			return versionKey.get(n);
		}
		
		public ArrayList<byte[]> getVersionKeys(){
			return versionKey;
		}
		
		public int getCurrent(){
			return versionKey.size();
		}
		
		public void addVersionKey(byte[] key){
			versionKey.add(key);
		}
	}
	
}
