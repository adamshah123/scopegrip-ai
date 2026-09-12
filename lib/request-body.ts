export class BodyTooLarge extends Error {}
export async function boundedText(req:Request,maxBytes:number):Promise<string> {
 const declared=Number(req.headers.get('content-length'));
 if(Number.isFinite(declared)&&declared>maxBytes)throw new BodyTooLarge();
 if(!req.body)return '';
 const reader=req.body.getReader();const chunks:Uint8Array[]=[];let length=0;
 try {while(true){const {value,done}=await reader.read();if(done)break;length+=value.byteLength;if(length>maxBytes){await reader.cancel();throw new BodyTooLarge();}chunks.push(value);}}
 finally {reader.releaseLock();}
 const bytes=new Uint8Array(length);let offset=0;for(const chunk of chunks){bytes.set(chunk,offset);offset+=chunk.byteLength;}
 return new TextDecoder('utf-8',{fatal:true}).decode(bytes);
}
