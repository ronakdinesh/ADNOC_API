import React, { useState } from 'react';
import { 
  Box, 
  Heading, 
  Text, 
  FormControl, 
  FormLabel, 
  Input, 
  Button, 
  VStack,
  Card,
  CardBody,
  useToast,
  Icon,
  Flex,
  Progress
} from '@chakra-ui/react';
import { FiUpload, FiCheckCircle, FiAlertTriangle } from 'react-icons/fi';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';

const UploadData = () => {
  const [file, setFile] = useState(null);
  const [tenantId, setTenantId] = useState('');
  const [incidentId, setIncidentId] = useState('');
  const [isUploading, setIsUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const toast = useToast();
  const navigate = useNavigate();

  const handleFileChange = (e) => {
    if (e.target.files.length > 0) {
      setFile(e.target.files[0]);
    }
  };

  const handleUpload = async (e) => {
    e.preventDefault();
    
    if (!file) {
      toast({
        title: 'No file selected',
        description: 'Please select an Excel file to upload',
        status: 'warning',
        duration: 4000,
        isClosable: true,
      });
      return;
    }

    try {
      setIsUploading(true);
      setUploadProgress(0);
      
      // Create form data
      const formData = new FormData();
      formData.append('file', file);
      
      if (tenantId) formData.append('tenant_id', tenantId);
      if (incidentId) formData.append('incident_id', incidentId);
      
      // Upload with progress tracking
      const response = await axios.post('/api/incidents/upload', formData, {
        headers: {
          'Content-Type': 'multipart/form-data'
        },
        onUploadProgress: (progressEvent) => {
          const progress = Math.round((progressEvent.loaded * 100) / progressEvent.total);
          setUploadProgress(progress);
        }
      });
      
      // Success!
      toast({
        title: 'Upload successful',
        description: `Analyzed ${response.data.total_incidents} incidents successfully`,
        status: 'success',
        duration: 5000,
        isClosable: true,
      });
      
      // Navigate to dashboard to see results
      navigate('/');
      
    } catch (error) {
      console.error('Upload error:', error);
      toast({
        title: 'Upload failed',
        description: error.response?.data?.error || 'An error occurred during upload',
        status: 'error',
        duration: 5000,
        isClosable: true,
      });
    } finally {
      setIsUploading(false);
    }
  };

  return (
    <Box>
      <Heading size="lg" mb={6}>Upload Incident Data</Heading>
      
      <Card borderWidth="1px" borderRadius="lg" overflow="hidden" boxShadow="md">
        <CardBody>
          <VStack as="form" onSubmit={handleUpload} spacing={4} align="flex-start">
            <FormControl isRequired>
              <FormLabel>Incident Data File (Excel format)</FormLabel>
              <Flex direction="column" gap={2}>
                <Input
                  type="file"
                  accept=".xlsx,.xls"
                  onChange={handleFileChange}
                  py={1}
                  disabled={isUploading}
                />
                {file && (
                  <Text fontSize="sm" color="green.500">
                    <Icon as={FiCheckCircle} mr={1} />
                    {file.name} ({Math.round(file.size / 1024)} KB)
                  </Text>
                )}
              </Flex>
            </FormControl>
            
            <FormControl>
              <FormLabel>Tenant ID (Optional)</FormLabel>
              <Input 
                value={tenantId} 
                onChange={(e) => setTenantId(e.target.value)} 
                disabled={isUploading}
                placeholder="Filter by specific tenant"
              />
            </FormControl>
            
            <FormControl>
              <FormLabel>Incident ID (Optional)</FormLabel>
              <Input 
                value={incidentId} 
                onChange={(e) => setIncidentId(e.target.value)} 
                disabled={isUploading}
                placeholder="Filter by specific incident"
              />
            </FormControl>
            
            {isUploading && (
              <Box width="100%">
                <Text mb={2}>Uploading and analyzing...</Text>
                <Progress value={uploadProgress} size="sm" colorScheme="brand" />
              </Box>
            )}
            
            <Box w="100%" pt={2}>
              <Button 
                type="submit" 
                colorScheme="brand" 
                isLoading={isUploading}
                loadingText="Uploading"
                leftIcon={<FiUpload />}
                width={{ base: "100%", md: "auto" }}
              >
                Upload and Analyze
              </Button>
            </Box>
          </VStack>
        </CardBody>
      </Card>
      
      <Card mt={8} bg="blue.50" p={4}>
        <CardBody>
          <Flex align="center" mb={2}>
            <Icon as={FiAlertTriangle} mr={2} color="blue.500" />
            <Text fontWeight="bold">Upload Tips</Text>
          </Flex>
          <Text fontSize="sm">
            Upload an Excel file containing security incident data to analyze. 
            The file should have columns like IncidentNumber, LastModifiedTime, 
            Status, Severity, TenantId, and optionally Comments.
          </Text>
        </CardBody>
      </Card>
    </Box>
  );
};

export default UploadData;