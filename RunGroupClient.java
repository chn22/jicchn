import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.List;


public class RunGroupClient{
	
	
	
	public static void main(String args[]){
		GroupClient groupClient = new GroupClient();
		FileClient fileClient = new FileClient();
		String input = null;
		BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
		UserToken token = null;
		//connect to the group server
		groupClient.connect("localhost",8765);
		boolean FSConnected = false;
		String usert = "";
		
		try{
			while(token == null){
				System.out.println("Enter your username");
				System.out.print(" > ");
				usert = in.readLine();
				token = groupClient.getToken(usert);
				if(token == null){
					System.out.println("not a valid user");
				}
			}
		}catch(Exception e){
			System.err.println(e);
		}
		
		//loop to wait for command
		do{
			token = groupClient.getToken(usert);
			try{
				System.out.println("Enter command, or type \"DISCONNECT\" to disconnect from groupserver.");
				System.out.print(" > ");	
			    input = in.readLine();
			}
			catch(Exception e){
			   System.err.println(e);
			}
			if(input.toUpperCase().equals("CUSER")){
				System.out.println("Enter the username to create");
				System.out.print(" > ");	
				String username = null;
				try {
					username = in.readLine().toLowerCase();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				boolean result = groupClient.createUser(username, token);
				if(result){
					System.out.println("success");
				}
			}
			else if(input.toUpperCase().equals("DUSER")){
				System.out.println("Enter the username to delete");
				System.out.print(" > ");	
				String username = null;
				try {
					username = in.readLine().toLowerCase();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				boolean result = groupClient.deleteUser(username, token);
				if(result){
					System.out.println("success");
				}
			}
			else if(input.toUpperCase().equals("CGROUP")){
				System.out.println("Enter the groupname to create");
				System.out.print(" > ");	
				String groupname = null;
				try {
					groupname = in.readLine().toLowerCase();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				boolean result = groupClient.createGroup(groupname, token);
				if(result){
					System.out.println("success");
				}
			}
			else if(input.toUpperCase().equals("DGROUP")){
				System.out.println("Enter the groupname to delete");
				System.out.print(" > ");	
				String groupname = null;
				try {
					groupname = in.readLine().toLowerCase();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				boolean result = groupClient.deleteGroup(groupname, token);
				if(result){
					System.out.println("success");
				}
			}
			else if(input.toUpperCase().equals("LMEMBERS")){
				System.out.println("Enter the groupname");
				System.out.print(" > ");	
				String groupname = null;
				try {
					groupname = in.readLine().toLowerCase();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				List<String> result = groupClient.listMembers(groupname, token);
				if(result != null){
					System.out.println("number of members: " + result.size());
					for(int i = 0; i < result.size(); i++){
						System.out.println(result.get(i));
					}
					
				}
				else System.out.println("is null");
			}
			else if(input.toUpperCase().equals("AUSERTOGROUP")){	
				String username = null;
				String groupname = null;
				try {
					System.out.println("Enter the username");
					System.out.print(" > ");
					username = in.readLine().toLowerCase();
					System.out.println("Enter the groupname");
					System.out.print(" > ");
					groupname = in.readLine().toLowerCase();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				boolean result = groupClient.addUserToGroup(username, groupname, token);
				if(result){
					System.out.println("success");
				}
				else
				{
					System.out.println("Add user not success!");
				}
			}
			else if(input.toUpperCase().equals("RUSERFROMGROUP")){	
				String username = null;
				String groupname = null;
				try {
					System.out.println("Enter the username");
					System.out.print(" > ");
					username = in.readLine().toLowerCase();
					System.out.println("Enter the groupname");
					System.out.print(" > ");
					groupname = in.readLine().toLowerCase();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				boolean result = groupClient.deleteUserFromGroup(username, groupname, token);
				if(result){
					System.out.println("success");
				}
			}
			else if(input.toUpperCase().equals("DISCONNECT")){
				if(FSConnected)
				{
					fileClient.disconnect();
				}
				groupClient.disconnect();
			}
			else if(input.toUpperCase().equals("FSCONNECT"))
			{
				if(!FSConnected)
				{
					fileClient.connect("localhost",4321);
					FSConnected = true;
					System.out.println("Connected to File Server Successfully");
				}
				else
				{
					System.out.println("Already Connected to File Server");
				}
			}
			else if(input.toUpperCase().equals("FSDISCONNECT"))
			{
				if(!FSConnected)
				{
					System.out.println("File Server is not connected!");
				}
				else
				{
					fileClient.disconnect();
					FSConnected = false;
					System.out.println("Successfully disconnected from File Server");
				}
			}
			else if(input.toUpperCase().equals("LISTFILES"))
			{
				if(!FSConnected)
				{
					System.out.println("File Server is not connected!");
				}
				else
				{
					List<String> filelist = fileClient.listFiles(token);
					for(String filename : filelist)
					{
						System.out.println(filename);
					}
				}
			}
			else if(input.toUpperCase().equals("UPLOAD"))
			{
				if(!FSConnected)
				{
					System.out.println("File Server is not connected!");
				}
				else
				{
					String sourceFile = null;
					String destFile = null;
					String group = null;
					try {
						System.out.println("Enter the sourceFile");
						System.out.print(" > ");
						sourceFile = in.readLine().toLowerCase();
						System.out.println("Enter the name to be saved in File Server");
						System.out.print(" > ");
						destFile = in.readLine().toLowerCase();
						System.out.println("Enter the groupname");
						System.out.print(" > ");
						group = in.readLine().toLowerCase();
					} catch (IOException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
					boolean result = fileClient.upload(sourceFile, destFile, group, token);
					if(result){
						System.out.println("Upload Success");
					}
					else
					{
						System.out.println("Upload Failed");
					}
				}
			}
			else if(input.toUpperCase().equals("DOWNLOAD"))
			{
				if(!FSConnected)
				{
					System.out.println("File Server is not connected!");
				}
				else
				{
					String sourceFile = null;
					String destFile = null;
					try {
						System.out.println("Enter the sourceFile");
						System.out.print(" > ");
						sourceFile = in.readLine().toLowerCase();
						System.out.println("Enter the name to be saved of the downloaded file");
						System.out.print(" > ");
						destFile = in.readLine().toLowerCase();
					} catch (IOException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
					boolean result = fileClient.download(sourceFile, destFile, token);
					if(result){
						System.out.println("Download Success");
					}
					else
					{
						System.out.println("Download Failed");
					}
				}
			}
			else if(input.toUpperCase().equals("DELETE"))
			{
				if(!FSConnected)
				{
					System.out.println("File Server is not connected!");
				}
				else
				{
					String filename = null;
					try {
						System.out.println("Enter the filename to be deleted");
						System.out.print(" > ");
						filename = in.readLine().toLowerCase();
					} catch (IOException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
					boolean result = fileClient.delete(filename, token);
					if(result){
						System.out.println("Delete Success");
					}
					else
					{
						System.out.println("Delete Failed");
					}
				}
			}
			else
			{
				System.out.println("Command not valid!");
			}
			
			
		}while(!input.toUpperCase().equals("DISCONNECT"));
		
	}
}