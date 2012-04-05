import java.util.ArrayList;

class Versions implements java.io.Serializable{
			private static final long serialVersionUID = -4384386018799891092L;
			private String groupName;
			private ArrayList<Integer> versions;
			
			public Versions(String group){
				groupName = group;
				versions = new ArrayList<Integer>();
			}
			
			public Versions(String group, int n){
				groupName = group;
				versions = new ArrayList<Integer>();
				versions.add(n);
			}
			
			public String getGroupName(){
				return groupName;
			}
			
			public void addVersion(int n){
				versions.add(n);
			}
			
			public ArrayList<Integer> getVersions(){
				return versions;
			}
			
			public boolean checkVersion(int n){
				return versions.contains(n);
			}
		}