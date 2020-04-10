**Auditee: APIs for five services**  
  
1. Generate: Call the "generate" function in notarize file to generate proof, return the filename;  
2. Download: Download the proof file by giving a specific filename;    
3. Upload: Create a .pgsg file according to generation time and session id. Write request content into a file and save it into the proof folder;  
4. Review: Call "review" function in reviewer file, and verify the proof file;   
5. Convert: Call the "convert" function in reviewer file. Convert the proof file into Displayable format.   