/** Synthetic host protocol conversion only. The host remains responsible for enforcing a deny. */
export function toNmzpEvaluation(raw){
  if(!raw || typeof raw!=="object" || Array.isArray(raw)
    || typeof raw.eventId!=="string" || !/^[a-z0-9-]{1,128}$/i.test(raw.eventId)
    || raw.tool!=="WebFetch" || typeof raw.url!=="string" || raw.url.length<1 || raw.url.length>1024){
    throw new Error("adapter_input_invalid");
  }
  return {eventId:raw.eventId,agent:"custom-helper",source:"hook",tool_name:"WebFetch",
    tool_input:{url:raw.url}};
}
