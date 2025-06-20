1) Check whether the folder have all the required extension files below:
  .sln, 
  .vcxproj, 
  .vcxproj.filters, 
  .vcxproj.users,
  main.c,
  main.exe
2) Open microsoft visual studio and create a new project > select empty project as the type of project.
3) Set the system to x64 (64 bits OS) and the configuration to 'Release'.
4) Open the main.c file by clicking on the folder icon bar just below the navbar.
5) After opeing of the file go to 'Project' > 'Properties' > 'General' then in the 'output directory' make it sure that  it shows "$(SolutionDir)x64\$(Configuration)\" and in the 'Intermediate Directory' as "$(ProjectDir)x64\Release\intermediate\" if not manually enter this.
6) Check the configuration type to be '.exe' and the 'windows SDK version as the latest version'.
7) In 'configuration properties' > 'Advanced' > 'Character set' as "Use Multibyte Character Set".
8) In 'C/C++' > 'General' > check that the 'Debug Information Format' is set to 'Program Database (/Zi)'
9) In the same check for 'Warning Level' as 'Level1' and 'SDL checks' as 'no (/sdl-)'
10) In 'C/C++' > 'Advanced' > make the code 'Compile As' : Compile as C Code (/TC)  
11) In 'Linker' > 'General' > make the 'Output Directory' as '$(OutDir)BaseNEncoder.exe'. and keep the 'System' as 'Console'.
12) Click on Apply then OK not directly on OK.(Otherwise it may not track the changes)
13) In 'View' on the Navbar open 'Solution explorer' and compile the solution with the foldername.sln.
14) In the 'Source Files' insert the main.c file by dropdown, and normally place .sln file in the solution explorer but not in the 'source files' folder, and all other files mentioned in (1).
15) Click on 'Build Solution' and then check the extension of file as .exe in the 'output window'.
16) Here I have deleted the folder 'BaseN' after the obtaination of required results bcoz my project name was 'BaseNEncoder' and also needed to have all the files inserted in the solution explorer, which created confusion after pushing it to git, *But remember there will be 2 folders with the saem content but after the building of the solution the project folder will contain the .exe file*.
17) Now create a .bin file containing some random hex bits like the 0xff, 0x28, 0xdf..........
18) *Note: the exe file and the .bin file must be in the same folder*.
19) Open windows powershell and cd to the directory where the .bin and .exe files are kept 
(In my case it was MsfCalcx64.bin and CyberSec.exe)
20) Now paste the file names '.\CyberSec.exe .\MsfCalcx64.bin' and hit enter.
21) It will create a '.BaseN' extension file and will be located in the same folder where the .exe and .bin are there.
22) Finally now place the .bin and .BaseN file in the 'pestudio' platform for checking the entropy levels.