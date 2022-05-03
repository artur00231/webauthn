

include(FetchContent)
FetchContent_Declare(
	SQLiteCpp
	# Specify the commit you depend on and update it regularly.
	URL https://github.com/SRombauts/SQLiteCpp/archive/refs/tags/3.1.1.zip
)
FetchContent_MakeAvailable(SQLiteCpp)

add_executable(Example
	Client.cpp
	Server.cpp
	main.cpp
)

target_link_libraries(Example PRIVATE Webauthn WebauthnClient CBORLib Crypto SQLiteCpp)