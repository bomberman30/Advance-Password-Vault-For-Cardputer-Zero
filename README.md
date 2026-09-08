how to build from source?
first add sodium to CMakeLists.txt
find
target_link_libraries(${PROJECT_NAME}
and add sodium at the end like that
target_link_libraries(${PROJECT_NAME}
    PRIVATE
        ${PROJECT_NAME}_platform
        ${PROJECT_NAME}_core
        ${PROJECT_NAME}_model
        ${PROJECT_NAME}_view
        ${PROJECT_NAME}_viewmodel
        sodium
)
and then run the command to download sodium
cmake --build --preset cp0-cross-rel

use the same instruction like the cardputer zero tamplate https://github.com/bomberman30/CardputerZeroTemplate but replace the src folder with the src folder from this repo
