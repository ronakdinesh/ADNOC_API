import React from 'react';
import { 
  Box, 
  Flex, 
  Heading, 
  Button, 
  HStack,
  useColorMode,
  useColorModeValue
} from '@chakra-ui/react';
import { Link as RouterLink } from 'react-router-dom';
import { MoonIcon, SunIcon } from '@chakra-ui/icons';

const Navbar = () => {
  const { colorMode, toggleColorMode } = useColorMode();
  const bgColor = useColorModeValue('white', 'gray.800');
  const borderColor = useColorModeValue('gray.200', 'gray.700');

  return (
    <Box 
      as="nav" 
      w="100%" 
      bg={bgColor} 
      boxShadow="sm" 
      borderBottom="1px" 
      borderColor={borderColor} 
      position="sticky" 
      top="0" 
      zIndex="1000"
    >
      <Flex 
        h="4rem" 
        maxW="1400px" 
        mx="auto" 
        px={4} 
        align="center" 
        justify="space-between"
      >
        <Heading 
          as={RouterLink} 
          to="/" 
          size="lg" 
          fontWeight="bold" 
          color="brand.500"
        >
          Sentinel Analyst
        </Heading>

        <HStack spacing={4}>
          <Button 
            as={RouterLink} 
            to="/" 
            variant="ghost"
            color="gray.600"
            _hover={{ color: 'brand.500' }}
          >
            Dashboard
          </Button>
          
          <Button 
            as={RouterLink} 
            to="/upload" 
            variant="ghost"
            color="gray.600"
            _hover={{ color: 'brand.500' }}
          >
            Upload Data
          </Button>
          
          <Button onClick={toggleColorMode} size="sm" variant="ghost">
            {colorMode === 'light' ? <MoonIcon /> : <SunIcon />}
          </Button>
        </HStack>
      </Flex>
    </Box>
  );
};

export default Navbar; 