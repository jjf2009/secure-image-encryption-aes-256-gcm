/**
 * COMPRESSION.JS
 * ==============
 * Provides lossless binary compression utilities using the browser's 
 * native CompressionStream and DecompressionStream APIs.
 * 
 * WHY GZIP?
 * - Widely supported standard.
 * - Excellent balance between compression speed and ratio.
 * - Lossless: guaranteed bit-for-bit restoration of original data.
 */

/**
 * Compresses a Uint8Array using Gzip.
 * 
 * @param {Uint8Array} data - The raw binary data to compress
 * @returns {Promise<Uint8Array>} Compressed binary data
 */
export const compressData = async (data) => {
  if (!data || data.length === 0) return data;
  
  try {
    const stream = new Blob([data]).stream();
    const compressionStream = new CompressionStream("gzip");
    const compressedStream = stream.pipeThrough(compressionStream);
    
    // Collect the stream into a single buffer
    const response = new Response(compressedStream);
    const buffer = await response.arrayBuffer();
    
    return new Uint8Array(buffer);
  } catch (error) {
    console.error("Compression failed:", error);
    // Fallback: return original data if compression fails
    return data;
  }
};

/**
 * Decompresses a Gzip-compressed Uint8Array.
 * 
 * @param {Uint8Array} data - The compressed binary data
 * @returns {Promise<Uint8Array>} Decompressed original binary data
 */
export const decompressData = async (data) => {
  if (!data || data.length === 0) return data;
  
  try {
    const stream = new Blob([data]).stream();
    const decompressionStream = new DecompressionStream("gzip");
    const decompressedStream = stream.pipeThrough(decompressionStream);
    
    // Collect the stream into a single buffer
    const response = new Response(decompressedStream);
    const buffer = await response.arrayBuffer();
    
    return new Uint8Array(buffer);
  } catch (error) {
    console.error("Decompression failed:", error);
    throw new Error("Failed to decompress data. The data may be corrupt.");
  }
};
