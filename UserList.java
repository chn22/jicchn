/* This list represents the users on the server */
import java.util.*;


	public class UserList implements java.io.Serializable {
	
		/**
		 * 
		 */
		private static final long serialVersionUID = 7600343803563417992L;
		private Hashtable<String, User> list = new Hashtable<String, User>();
		
		public synchronized void addUser(String username)
		{
			User newUser = new User();
			list.put(username, newUser);
		}
		
		public synchronized void deleteUser(String username)
		{
			list.remove(username);
		}
		
		public synchronized boolean checkUser(String username)
		{
			if(list.containsKey(username))
			{
				return true;
			}
			else
			{
				return false;
			}
		}
		
		public synchronized ArrayList<String> getUserGroups(String username)
		{
			return list.get(username).getGroups();
		}
		
		public synchronized ArrayList<String> getUserOwnership(String username)
		{
			return list.get(username).getOwnership();
		}
		
		public synchronized void addGroup(String user, String groupname)
		{
			list.get(user).addGroup(groupname);
		}
		
		public synchronized void removeGroup(String user, String groupname)
		{
			list.get(user).removeGroup(groupname);
		}
		
		public synchronized void addOwnership(String user, String groupname)
		{
			list.get(user).addOwnership(groupname);
		}
		
		public synchronized void removeOwnership(String user, String groupname)
		{
			list.get(user).removeOwnership(groupname);
		}
		
		public synchronized byte[] getPassword(String user){
			return list.get(user).getPassword();
		}
		
		public synchronized void setPassword(String user, byte[] password){
			list.get(user).setPassword(password);
		}
		
		public synchronized void addVersion(String user, String groupname, int n){
			list.get(user).addVersion(groupname, n);
		}
		
		public synchronized ArrayList<Integer> getVersions(String user, String groupname){
			return list.get(user).getVersions(groupname);
		}
		
	class User implements java.io.Serializable {

		/**
		 * 
		 */
		private static final long serialVersionUID = -6699986336399821598L;
		private ArrayList<String> groups;
		private ArrayList<String> ownership;
		private byte[] password;
		private Hashtable<String,Versions> versions = new Hashtable<String, Versions>();
		
		public User()
		{
			groups = new ArrayList<String>();
			ownership = new ArrayList<String>();
		}
		
		public ArrayList<String> getGroups()
		{
			return groups;
		}
		
		public ArrayList<String> getOwnership()
		{
			return ownership;
		}
		
		public void addGroup(String group)
		{
			groups.add(group);
		}
		
		public void removeGroup(String group)
		{
			if(!groups.isEmpty())
			{
				if(groups.contains(group))
				{
					groups.remove(groups.indexOf(group));
				}
			}
		}
		
		public void addOwnership(String group)
		{
			ownership.add(group);
		}
		
		public void removeOwnership(String group)
		{
			if(!ownership.isEmpty())
			{
				if(ownership.contains(group))
				{
					ownership.remove(ownership.indexOf(group));
				}
			}
		}
		
		public byte[] getPassword()
		{
			return password;
		}
		
		public void setPassword(byte[] p){
			password = p;
		}
		
		public ArrayList<Integer> getVersions(String group){
			return versions.get(group).getVersions();
		}
		
		public void addVersion(String group, int n){
			if(versions.containsKey(group)){
				versions.get(group).addVersion(n);
			}
			else{
				Versions v = new Versions(group, n);
				versions.put(group, v);
			}
			
		}
		
		public boolean checkVersion(String group, int n){
			return versions.get(group).checkVersion(n);
		}
		
	}
	
}	
