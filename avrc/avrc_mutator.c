// gatt_mutator.c

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define MAX_PACKETS 256
#define MAX_PACKET_SIZE 512

typedef struct {
    uint16_t len;
    uint8_t data[MAX_PACKET_SIZE];
} Packet;

static uint32_t xorshift32(uint32_t *state)
{
    uint32_t x=*state;

    x ^= x<<13;
    x ^= x>>17;
    x ^= x<<5;

    *state=x;

    return x;
}

static uint32_t rnd(uint32_t *seed,uint32_t max)
{
    if(max==0)
        return 0;

    return xorshift32(seed)%max;
}

static size_t parse_packets(
    const uint8_t *data,
    size_t size,
    Packet *packets)
{
    size_t count=0;
    size_t pos=0;

    while(pos+2<=size && count<MAX_PACKETS)
    {
        uint16_t len=
            data[pos] |
            (data[pos+1]<<8);

        pos+=2;

        size_t remain=
            size-pos;

        // Clamp malformed length
        if(len>remain)
            len=remain;

        if(len>MAX_PACKET_SIZE)
            len=MAX_PACKET_SIZE;

        packets[count].len=len;

        memcpy(
            packets[count].data,
            data+pos,
            len);

        pos+=len;

        count++;
    }

    return count;
}

static size_t serialize_packets(
    Packet *packets,
    size_t count,
    uint8_t *out,
    size_t maxsize)
{
    size_t pos=0;

    for(size_t i=0;i<count;i++)
    {
        size_t total=
            2+packets[i].len;

        if(pos+total>maxsize)
            break;

        out[pos]=packets[i].len&0xff;
        out[pos+1]=packets[i].len>>8;

        pos+=2;

        memcpy(
            out+pos,
            packets[i].data,
            packets[i].len);

        pos+=packets[i].len;
    }

    return pos;
}

static uint8_t gatt_ops[]={
    0x02, // MTU
    0x04, // FIND_INFO
    0x06, // FIND_TYPE
    0x08, // READ_BY_TYPE
    0x0A, // READ
    0x0C, // READ_BLOB
    0x0E, // READ_MULTI
    0x10, // READ_GROUP
    0x12, // WRITE
    0x16, // PREP_WRITE
    0x18, // EXEC_WRITE
    0x20
};

extern size_t LLVMFuzzerCustomMutator(
    uint8_t *Data,
    size_t Size,
    size_t MaxSize,
    unsigned Seed)
{
    Packet packets[MAX_PACKETS];

    uint32_t seed=Seed;

    size_t count=
        parse_packets(
            Data,
            Size,
            packets);

    switch(rnd(&seed,6))
    {
        case 0: // mutate packet bytes
        {
            if(count==0)
                break;

            Packet *p=
                &packets[
                    rnd(&seed,count)];

            if(p->len)
            {
                size_t off=
                    rnd(
                        &seed,
                        p->len);

                p->data[off]^=
                    rnd(&seed,256);
            }

            break;
        }

        case 1: // mutate opcode
        {
            if(count==0)
                break;

            Packet *p=
                &packets[
                    rnd(&seed,count)];

            if(p->len)
            {
                p->data[0]=
                    gatt_ops[
                        rnd(
                            &seed,
                            sizeof(gatt_ops))];
            }

            break;
        }

        case 2: // add packet
        {
            if(count>=MAX_PACKETS)
                break;

            Packet *p=
                &packets[count];

            p->len=
                rnd(&seed,32);

            for(size_t i=0;i<p->len;i++)
                p->data[i]=
                    rnd(&seed,256);

            if(p->len)
                p->data[0]=
                    gatt_ops[
                        rnd(
                            &seed,
                            sizeof(gatt_ops))];

            count++;

            break;
        }

        case 3: // delete packet
        {
            if(count==0)
                break;

            size_t victim=
                rnd(
                    &seed,
                    count);

            memmove(
                &packets[victim],
                &packets[victim+1],
                (count-victim-1)
                *sizeof(Packet));

            count--;

            break;
        }

        case 4: // duplicate packet
        {
            if(count==0 ||
               count>=MAX_PACKETS)
                break;

            size_t src=
                rnd(&seed,count);

            packets[count]=
                packets[src];

            count++;

            break;
        }

        case 5: // swap packets
        {
            if(count<2)
                break;

            size_t a=
                rnd(&seed,count);

            size_t b=
                rnd(&seed,count);

            Packet tmp=
                packets[a];

            packets[a]=
                packets[b];

            packets[b]=
                tmp;

            break;
        }
    }

    return serialize_packets(
        packets,
        count,
        Data,
        MaxSize);
}

extern size_t LLVMFuzzerCustomCrossOver(
    const uint8_t *Data1,
    size_t Size1,
    const uint8_t *Data2,
    size_t Size2,
    uint8_t *Out,
    size_t MaxOutSize,
    unsigned Seed)
{
    Packet p1[MAX_PACKETS];
    Packet p2[MAX_PACKETS];
    Packet out[MAX_PACKETS];

    uint32_t seed=Seed;

    size_t n1=
        parse_packets(
            Data1,
            Size1,
            p1);

    size_t n2=
        parse_packets(
            Data2,
            Size2,
            p2);

    size_t out_count=0;

    while(out_count<MAX_PACKETS)
    {
        int pick=
            rnd(&seed,2);

        if(pick==0 && n1)
        {
            out[out_count++]=
                p1[
                    rnd(
                        &seed,
                        n1)];
        }
        else if(n2)
        {
            out[out_count++]=
                p2[
                    rnd(
                        &seed,
                        n2)];
        }

        if(rnd(&seed,4)==0)
            break;
    }

    return serialize_packets(
        out,
        out_count,
        Out,
        MaxOutSize);
}

#ifdef MUT_TESTING

int main()
{
    uint8_t buf1[4096];
    uint8_t buf2[4096];
    uint8_t out[4096];

    for(int i=0;i<100000;i++)
    {
        size_t s1=
            rand()%1000;

        size_t s2=
            rand()%1000;

        for(size_t j=0;j<s1;j++)
            buf1[j]=rand();

        for(size_t j=0;j<s2;j++)
            buf2[j]=rand();

        LLVMFuzzerCustomMutator(
            buf1,
            s1,
            sizeof(buf1),
            rand());

        LLVMFuzzerCustomCrossOver(
            buf1,
            s1,
            buf2,
            s2,
            out,
            sizeof(out),
            rand());
    }

    printf("OK\n");
}

#endif
