"""Base LDAP message builder."""

from abc import ABC
from typing import AsyncGenerator

from asn1 import Classes, Encoder, Numbers
from pydantic import BaseModel, Field, validator

from .asn1parser import asn1todict
from .dialogue import Session
from .ldap_requests import BaseRequest, protocol_id_map
from .ldap_responses import BaseResponse


class LDAPMessage(ABC, BaseModel):
    """Base message structure. Pydantic for types validation."""

    message_id: int = Field(..., alias='messageID')
    protocol_op: int = Field(..., alias='protocolOP')
    context: BaseRequest | BaseResponse = Field()
    controls: int | None = 0

    @validator('controls')
    def default_controls(cls, v) -> int:  # noqa: N805
        """Set zero if None."""
        if v is None:
            return 0
        return v


class LDAPResponseMessage(LDAPMessage):
    """Response message."""

    context: BaseResponse

    def encode(self) -> bytes:
        """Encode message to asn1."""
        enc = Encoder()
        enc.start()
        enc.enter(Numbers.Sequence)
        enc.write(self.message_id, Numbers.Integer)
        enc.enter(nr=self.context.PROTOCOL_OP, cls=Classes.Application)
        self.context.to_asn1(enc)
        enc.leave()
        enc.leave()
        return enc.output()


class LDAPRequestMessage(LDAPMessage):
    """Request message interface."""

    context: BaseRequest

    @classmethod
    def from_bytes(cls, source: bytes):
        """Create message from bytes."""
        output = asn1todict(source)
        sequence = output.pop('field-0')[0]

        if sequence.tag_id.value != Numbers.Sequence:
            raise ValueError('Wrong schema')

        seq_fields = output[sequence.value]
        message_id, protocol = seq_fields[:1]

        try:
            controls = seq_fields[2].tag_id.value
        except IndexError:
            controls = 0

        context = protocol_id_map[protocol.tag_id.value].from_data(output)
        return cls(
            messageID=message_id.value,
            protocolOP=protocol.tag_id.value,
            context=context,
            controls=controls,
        )

    async def create_response(self, session: Session) -> \
            AsyncGenerator[LDAPResponseMessage, None]:
        """Call unique context handler.

        :yield LDAPResponseMessage: create response for context.
        """
        async for response in self.context.handle(session):
            yield LDAPResponseMessage(
                messageID=self.message_id,
                protocolOP=response.PROTOCOL_OP,
                context=response,
            )
