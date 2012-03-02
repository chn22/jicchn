/* This thread does all the work. It communicates with the client through Envelopes.
 * 
 */
import java.lang.Thread;
import java.net.Socket;
import java.io.*;
import java.util.*;

public class GroupThread extends Thread 
{
	private final Socket socket;
	private GroupServer my_gs;
	
	public GroupThread(Socket _socket, GroupServer _gs)
	{
		socket = _socket;
		my_gs = _gs;
	}
	
	public void run()
	{	
		
		boolean proceed = true;

		try
		{
			//Announces connection and opens object streams
			System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
			final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
			final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
			
			do
			{
				Envelope message = (Envelope)input.readObject();
				System.out.println("Request received: " + message.getMessage());
				Envelope response;
				
				if(message.getMessage().equals("GET"))//Client wants a token
				{
					String username = (String)message.getObjContents().get(0); //Get the username
					if(username == null)
					{
						response = new Envelope("FAIL");
						response.addObject(null);
						output.writeObject(response);
					}
					else
					{
						UserToken yourToken = createToken(username); //Create a token
						
						//Respond to the client. On error, the client will receive a null token
						response = new Envelope("OK");
						response.addObject(yourToken);
						output.writeObject(response);
					}
				}
				else if(message.getMessage().equals("CUSER")) //Client wants to create a user
				{
					if(message.getObjContents().size() < 2)
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");
						
						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								String username = (String)message.getObjContents().get(0); //Extract the username
								UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token
								if(createUser(username, yourToken))
								{
									response = new Envelope("OK"); //Success
								}
							}
						}
					}
					output.writeObject(response);
				}
				else if(message.getMessage().equals("DUSER")) //Client wants to delete a user
				{
					
					if(message.getObjContents().size() < 2)
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");
						
						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								String username = (String)message.getObjContents().get(0); //Extract the username
								UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token
								
								if(deleteUser(username, yourToken))
								{
									response = new Envelope("OK"); //Success
								}
							}
						}
					}
					
					output.writeObject(response);
				}
				else if(message.getMessage().equals("CGROUP")) //Client wants to create a group
				{

					if(message.getObjContents().size() < 2)
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");
						
						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								String groupname = (String)message.getObjContents().get(0); //Extract the groupname
								UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token
								
								if(createGroup(groupname, yourToken))
								{
									response = new Envelope("OK"); //Success
								}
							}
						}
					}
					
					output.writeObject(response);
					
				}
				else if(message.getMessage().equals("DGROUP")) //Client wants to delete a group
				{

					if(message.getObjContents().size() < 2)
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");
						
						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								String groupname = (String)message.getObjContents().get(0); //Extract the groupname
								UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token
								
								if(deleteGroup(groupname, yourToken))
								{
									response = new Envelope("OK"); //Success
								}
							}
						}
					}
					
					output.writeObject(response);
				}
				else if(message.getMessage().equals("LMEMBERS")) //Client wants a list of members in a group
				{
					if(message.getObjContents().size() < 2)
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");
						
						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								String groupname = (String)message.getObjContents().get(0); //Extract the groupname
								UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token
								ArrayList<String> memberList = listMember(groupname, yourToken);
								//if the requester is the owner of the group
								if(memberList != null)
								{
									response = new Envelope("OK"); //Success
									response.addObject(memberList);
								}
							}
						}
					}
					
					output.writeObject(response);
				}
				else if(message.getMessage().equals("AUSERTOGROUP")) //Client wants to add user to a group
				{
					if(message.getObjContents().size() < 3)
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");
						
						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								if(message.getObjContents().get(2) != null)
								{
									String username = (String)message.getObjContents().get(0); //Extract the username
									String groupname = (String)message.getObjContents().get(1); //Extract the groupname
									UserToken yourToken = (UserToken)message.getObjContents().get(2); //Extract the token
									if(addUserToGroup(username, groupname, yourToken))
									{
										response = new Envelope("OK"); //Success
									}
								}
							}
						}
					}
					
					output.writeObject(response);
				}
				else if(message.getMessage().equals("RUSERFROMGROUP")) //Client wants to remove user from a group
				{
					if(message.getObjContents().size() < 3)
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");
						
						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								if(message.getObjContents().get(2) != null)
								{
									String username = (String)message.getObjContents().get(0); //Extract the username
									String groupname = (String)message.getObjContents().get(1); //Extract the groupname
									UserToken yourToken = (UserToken)message.getObjContents().get(2); //Extract the token
									if(removeUserFromGroup(username, groupname, yourToken))
									{
										response = new Envelope("OK"); //Success
									}
								}
							}
						}
					}
					
					output.writeObject(response);
				}
				else if(message.getMessage().equals("DISCONNECT")) //Client wants to disconnect
				{
					socket.close(); //Close the socket
					proceed = false; //End this communication loop
				}
				else
				{
					response = new Envelope("FAIL"); //Server does not understand client request
					output.writeObject(response);
				}
			}while(proceed);	
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
	
	
	
	
	
	//Method to create tokens
	private UserToken createToken(String username) 
	{
		//Check that user exists
		if(my_gs.userList.checkUser(username))
		{
			//Issue a new token with server's name, user's name, and user's groups
			Date timestamp = new Date();
			UserToken yourToken = new Token(my_gs.name, username, my_gs.userList.getUserGroups(username), timestamp);
			return yourToken;
		}
		else
		{
			System.out.println("User does not exist!-----------------------");
			return null;
		}
	}
	
	
	//Method to create a user
	private boolean createUser(String username, UserToken yourToken)
	{
		String requester = yourToken.getSubject();
		
		//Check if requester exists
		if(my_gs.userList.checkUser(requester))
		{
			//Get the user's groups
			ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
			//requester needs to be an administrator
			if(temp.contains("admin"))
			{
				//Does user already exist?
				if(my_gs.userList.checkUser(username))
				{
					return false; //User already exists
				}
				else
				{
					my_gs.userList.addUser(username);
					return true;
				}
			}
			else
			{
				System.out.println("Requester is not an administrator!-----------------------");
				return false; //requester not an administrator
			}
		}
		else
		{
			System.out.println("Requester does not exist!-----------------------");
			return false; //requester does not exist
		}
	}
	
	//Method to delete a user
	private boolean deleteUser(String username, UserToken yourToken)
	{
		String requester = yourToken.getSubject();
		
		//Does requester exist?
		if(my_gs.userList.checkUser(requester))
		{
			ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
			//requester needs to be an administer
			if(temp.contains("admin"))
			{
				//Does user exist?
				if(my_gs.userList.checkUser(username))
				{
					//User needs deleted from the groups they belong
					ArrayList<String> deleteFromGroups = new ArrayList<String>();
					
					//This will produce a hard copy of the list of groups this user belongs
					for(int index = 0; index < my_gs.userList.getUserGroups(username).size(); index++)
					{
						deleteFromGroups.add(my_gs.userList.getUserGroups(username).get(index));
					}
					
					//Delete the user from the groups
					//If user is the owner, removeMember will automatically delete group!
					for(int index = 0; index < deleteFromGroups.size(); index++)
					{
						my_gs.groupList.removeMember(deleteFromGroups.get(index), username);
					}
					
					//If groups are owned, they must be deleted
					ArrayList<String> deleteOwnedGroup = new ArrayList<String>();
					
					//Make a hard copy of the user's ownership list
					for(int index = 0; index < my_gs.userList.getUserOwnership(username).size(); index++)
					{
						deleteOwnedGroup.add(my_gs.userList.getUserOwnership(username).get(index));
					}
					
					//Delete owned groups
					for(int index = 0; index < deleteOwnedGroup.size(); index++)
					{
						//Use the delete group method. Token must be created for this action
						Date timestamp = new Date();
						deleteGroup(deleteOwnedGroup.get(index), new Token(my_gs.name, username, deleteOwnedGroup, timestamp));
					}
					
					//Delete the user from the user list
					my_gs.userList.deleteUser(username);
					
					return true;	
				}
				else
				{
					System.out.println("User does not exist!---------------------------------------");
					return false; //User does not exist
				}
			}
			else
			{
				System.out.println("Requester is not an administrator!-----------------------");
				return false; //requester is not an administer
			}
		}
		else
		{
			System.out.println("Requester does not exist!-----------------------");
			return false; //requester does not exist
		}
	}
	
	
	private boolean createGroup(String groupName, UserToken yourToken){
		
		String requester = yourToken.getSubject();
		
		//Does requester exist?
		if(my_gs.userList.checkUser(requester))
		{
			
			//group not yet exists
			if(!my_gs.groupList.checkGroup(groupName))
			{
				my_gs.groupList.addGroup(groupName);
				my_gs.userList.addOwnership(requester, groupName);
				my_gs.userList.addGroup(requester, groupName);
				my_gs.groupList.addMember(groupName, requester);
				return true;
			}
			else
			{
				System.out.println("Group is already exist!---------------------------------");
				return false;
			}
		}
		else
		{
			System.out.println("Requester does not exist!-----------------------");
			return false;
		}
	}
	
	
	private boolean deleteGroup(String groupName, UserToken yourToken){
		
		String requester = yourToken.getSubject();
		
		//Does requester exist?
		if(my_gs.userList.checkUser(requester))
		{
			//Does the group exist?
			if(my_gs.groupList.checkGroup(groupName))
			{
				//if the requester is the owner of the group
				if(my_gs.userList.getUserOwnership(requester).contains(groupName))
				{		
					ArrayList<String> temp = my_gs.groupList.getMembers(groupName);
					for(int i = 0; i < temp.size(); i++){
						my_gs.userList.removeGroup(temp.get(i), groupName);
					}
					my_gs.groupList.deleteGroup(groupName);
					return true;
				}
				else{
					System.out.println("Requester is not the owner of the group!---------------------------------");
					return false;	
				}
			}
			else
			{
				System.out.println("Group does not exist!---------------------------------");
				return false;
			}
		}
		else
		{
			System.out.println("Requester does not exist!-----------------------");
			return false;
		}
	}
	// yourToken requests to list all members of groupName
	private ArrayList<String> listMember(String groupName, UserToken yourToken){
		
		String requester = yourToken.getSubject();
		
		//Does requester exist?
		if(my_gs.userList.checkUser(requester))
		{
			//Does the group exist?
			if(my_gs.groupList.checkGroup(groupName))
			{
				//if the requester is the owner of the group
				if(my_gs.userList.getUserOwnership(requester).contains(groupName))
				{
					System.out.println("listmembers: " + my_gs.groupList.getMembers(groupName));
					return my_gs.groupList.getMembers(groupName);
				}
				else
				{
					System.out.println("Requester is not the owner of the group!----------------");
					return null;
				}
			}
			else
			{
				System.out.println("Group does not exist!-----------------------------");
				return null;
			}
		}
		else
		{
			System.out.println("Requester does not exist!---------------------");
			return null;
		}
	}
	
	private boolean addUserToGroup(String username, String groupName, UserToken yourToken){
		String requester = yourToken.getSubject();
		
		//Does requester exist?
		if(my_gs.userList.checkUser(requester))
		{
			//Does the group exist?
			if(my_gs.groupList.checkGroup(groupName))
			{
				//Does the user exist?
				if(my_gs.userList.checkUser(username))
				{
					//if the requester is the owner of the group
					if(my_gs.userList.getUserOwnership(requester).contains(groupName))
					{
						//if the user is not yet in the group
						if(!my_gs.groupList.checkMembership(groupName, username))
						{
							my_gs.userList.addGroup(username, groupName);
							my_gs.groupList.addMember(groupName, username);
							return true;
							
						}
						else
						{
							System.out.println("User is already in group!--------------------------------");
							return false;
						}
					}
					else
					{
						System.out.println("User is not owner of the group!------------------------");
						return false;
					}
				}
				else
				{
					System.out.println("User does not exist!----------------------------------");
					return false;
				}
			}
			else
			{
				System.out.println("Group does not exist!----------------------------");
				return false;
			}
		}
		else
		{
			System.out.println("Requester does not exist!-------------------------------");
			return false;
		}
	}
	
	private boolean removeUserFromGroup(String username, String groupName, UserToken yourToken){
		String requester = yourToken.getSubject();
		
		//Does requester exist?
		if(my_gs.userList.checkUser(requester))
		{
			//Does the group exist?
			if(my_gs.groupList.checkGroup(groupName))
			{
				//Does the user exist?
				if(my_gs.userList.checkUser(username))
				{
					//if the requester is the owner of the group
					if(my_gs.userList.getUserOwnership(requester).contains(groupName))
					{
						//if the user is a member of the group
						if(my_gs.groupList.checkMembership(groupName, username))
						{
							my_gs.userList.removeGroup(username, groupName);
							my_gs.groupList.removeMember(groupName, username);
							return true;
						}
						else
						{
							System.out.println("User is not a member of the group!---------------------------");
							return false;
						}
					}
					else
					{
						System.out.println("Requester is not the owner of group!---------------------");
						return false;
					}
				}
				else
				{
					System.out.println("User does not exist!-------------------------");
					return false;
				}
			}
			else
			{
				System.out.println("Group does not exist!----------------------");
				return false;
			}
		}
		else
		{
			System.out.println("Requester does not exist!-----------------");
			return false;
		}
	}
}
