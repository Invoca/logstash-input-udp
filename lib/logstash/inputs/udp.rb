# encoding: utf-8
require "date"
require "logstash/util/buftok"
require "logstash/inputs/base"
require "logstash/namespace"
require "socket"

# Read messages as events over the network via udp. The only required
# configuration item is `port`, which specifies the udp port logstash
# will listen on for event streams.
#
class LogStash::Inputs::Udp < LogStash::Inputs::Base
  config_name "udp"

  default :codec, "plain"

  # The address which logstash will listen on.
  config :host, :validate => :string, :default => "0.0.0.0"

  # The port which logstash will listen on. Remember that ports less
  # than 1024 (privileged ports) may require root or elevated privileges to use.
  config :port, :validate => :number, :required => true

  # The maximum packet size to read from the network
  config :buffer_size, :validate => :number, :default => 8192

  # Number of threads processing packets
  config :workers, :validate => :number, :default => 2

  # This is the number of unprocessed UDP packets you can hold in memory
  # before packets will start dropping.
  config :queue_size, :validate => :number, :default => 2000

  public
  def initialize(params)
    super
    BasicSocket.do_not_reverse_lookup = true
    @buffers = {}
    @buffers_mutex = Mutex.new
  end # def initialize

  public
  def register
    @udp = nil
  end # def register

  public
  def run(output_queue)
    @output_queue = output_queue
    begin
      # udp server
      udp_listener(output_queue)
    rescue LogStash::ShutdownSignal
      # do nothing, shutdown was requested.
    rescue => e
      @logger.warn("UDP listener died", :exception => e, :backtrace => e.backtrace)
      sleep(5)
      retry
    end # begin
  end # def run

  private
  def udp_listener(output_queue)
    @logger.info("Starting UDP listener", :address => "#{@host}:#{@port}")

    if @udp && ! @udp.closed?
      @udp.close
    end

    @udp = UDPSocket.new(Socket::AF_INET)
    @udp.bind(@host, @port)

    @input_to_worker = SizedQueue.new(@queue_size)

    @input_workers = @workers.times do |i|
      @logger.debug("Starting UDP worker thread", :worker => i)
      Thread.new { inputworker(i) }
    end

    Thread.new { cleanup_buffers }

    while true
      #collect datagram message and add to queue
      payload, client = @udp.recvfrom(@buffer_size)
      @input_to_worker.push([payload, client])
    end
  ensure
    if @udp
      @udp.close_read rescue nil
      @udp.close_write rescue nil
    end
  end # def udp_listener

  def inputworker(number)
    LogStash::Util::set_thread_name("<udp.#{number}")
    begin
      while true
        payload, client = @input_to_worker.pop

        found = false
        buffer = nil
        @buffers_mutex.synchronize do
          buffer = @buffers[client] ||= { buffer: FileWatch::BufferedTokenizer.new, mutex: Mutex.new }
          @buffers[client][:last_used] = Time.now
        end

        buffer[:mutex].synchronize do
          buffer[:buffer].extract(payload).each do |line|
            @codec.decode(line) do |event|
              found = true
              decorate(event)
              event["host"] ||= client[3]

              # Look for very long fields indicative of udp reordering that somehow resulted in valid JSON
              if max_field_length(event.to_hash) < 1000
                @output_queue.push(event)
              else
                @logger.info("field too long #{event.to_hash.to_s}")
              end
            end
          end
        end

        if found
          @buffers_mutex.synchronize do
            @buffers.delete(client)
          end
        end
      end
    rescue => e
      @logger.error("Exception in inputworker", "exception" => e, "backtrace" => e.backtrace)
      retry
    end
  end # def inputworker

  def cleanup_buffers
    loop do
      @buffers_mutex.synchronize do
        before_size = @buffers.size
        @buffers.delete_if do |_client, buffer|
          buffer[:last_used] < Time.now - 60
        end

        purged = before_size - @buffers.size
        if purged > 0
          @logger.warn("Purged #{purged} stale buffers of #{before_size}")
        end
      end

      sleep 60
    end
  end

  def max_field_length(hash)
    hash.map do |k,v|
      if v.is_a?(Hash)
        max_field_length(v)
      else
        k.length
      end
    end.max || 0
  end

  public
  def teardown
    @udp.close if @udp && !@udp.closed?
  end

end # class LogStash::Inputs::Udp
